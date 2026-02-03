// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 IBM
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

//! This crate implements the virtual TPM interfaces for the TPM 2.0
//! Reference Implementation (by Microsoft)

/// Functions required to build the TPM 2.0 Reference Implementation libraries
#[cfg(not(any(test, fuzzing)))]
mod wrapper;

pub mod ek_templates;
pub mod ak_templates;
mod tss;

extern crate alloc;

use alloc::vec::Vec;

use core::ffi::c_void;
use libtcgtpm::bindings::{
    TPM_Manufacture, TPM_TearDown, _plat__LocalitySet, _plat__NVDisable, _plat__NVEnable,
    _plat__RunCommand, _plat__SetNvAvail, _plat__Signal_PowerOn, _plat__Signal_Reset,
};

use crate::{
    address::VirtAddr,
    protocols::{errors::SvsmReqError, vtpm::TpmPlatformCommand},
    types::PAGE_SIZE,
    vtpm::{
        tcgtpm::ek_templates::DEFAULT_PUBLIC_AREA, tcgtpm::ak_templates::PUBLIC_AREA_AK, TcgTpmSimulatorInterface, VtpmInterface,
        VtpmProtocolInterface, tcgtpm::tss::{EK,AK}
    },
};

// Definitions from "Trusted Platform Module Library Part 4: Supporting Routines – Code,
// Family “2.0”, Level 00, Revision 01.38"
const TPM_AK_HANDLE: u32 = 0x81000002;

#[derive(Debug, Clone, Default)]
pub struct TcgTpm {
    is_powered_on: bool,
    ek: Option<EK>,
    ak: Option<AK>,
}

impl TcgTpm {
    pub const fn new() -> TcgTpm {
        TcgTpm {
            is_powered_on: false,
            ek: None,
            ak: None
        }
    }

    fn teardown(&self) -> Result<(), SvsmReqError> {
        // SAFETY: FFI call. Return value is checked.
        let result = unsafe { TPM_TearDown() };
        match result {
            0 => Ok(()),
            rc => {
                log::error!("TPM_Teardown failed rc={}", rc);
                Err(SvsmReqError::incomplete())
            }
        }
    }

    fn manufacture(&self, first_time: i32) -> Result<i32, SvsmReqError> {
        // SAFETY: FFI call. Parameter and return values are checked.
        let result = unsafe { TPM_Manufacture(first_time) };
        match result {
            // TPM manufactured successfully
            0 => Ok(0),
            // TPM already manufactured
            1 => Ok(1),
            // TPM failed to manufacture
            rc => {
                log::error!("TPM_Manufacture failed rc={}", rc);
                Err(SvsmReqError::incomplete())
            }
        }
    }
}

const TPM_CMDS_SUPPORTED: &[TpmPlatformCommand] = &[TpmPlatformCommand::SendCommand];

impl VtpmProtocolInterface for TcgTpm {
    fn get_supported_commands(&self) -> &[TpmPlatformCommand] {
        TPM_CMDS_SUPPORTED
    }
}

pub const TPM_BUFFER_MAX_SIZE: usize = PAGE_SIZE;

impl TcgTpmSimulatorInterface for TcgTpm {
    fn send_tpm_command(&self, command: &[u8], locality: u8) -> Result<Vec<u8>, SvsmReqError> {
        if !self.is_powered_on {
            return Err(SvsmReqError::invalid_request());
        }
        if command.len() > TPM_BUFFER_MAX_SIZE {
            return Err(SvsmReqError::invalid_parameter());
        }

        // _plat__RunCommand() should define it `const` because it only uses
        // it as input, but unfortunately it doesn't. Anyway, this buffer
        // is only read during the FFI call.
        let request_ffi_p = command.as_ptr() as *mut u8;
        let request_ffi_size = command.len() as u32;

        let mut response_ffi = Vec::<u8>::with_capacity(TPM_BUFFER_MAX_SIZE);
        let mut response_ffi_p = response_ffi.as_mut_ptr();
        let mut response_ffi_size = TPM_BUFFER_MAX_SIZE as u32;

        // SAFETY: FFI calls. Parameters are checked. Both calls are void,
        // _plat__RunCommand() returns `response_ffi_size` value by reference
        // and it is validated.
        unsafe {
            _plat__LocalitySet(locality);
            _plat__RunCommand(
                request_ffi_size,
                request_ffi_p,
                &raw mut response_ffi_size,
                &raw mut response_ffi_p,
            );
            if response_ffi_size == 0 || response_ffi_size as usize > response_ffi.capacity() {
                return Err(SvsmReqError::invalid_request());
            }
            response_ffi.set_len(response_ffi_size as usize);
        }

        Ok(response_ffi)
    }

    fn signal_poweron(&mut self, only_reset: bool) -> Result<(), SvsmReqError> {
        if self.is_powered_on && !only_reset {
            return Ok(());
        }
        if only_reset && !self.is_powered_on {
            return Err(SvsmReqError::invalid_request());
        }
        if !only_reset {
            // SAFETY: FFI call. No parameter, return value is checked.
            let result = unsafe { _plat__Signal_PowerOn() };
            if result != 0 {
                log::error!("_plat__Signal_PowerOn failed rc={}", result);
                return Err(SvsmReqError::incomplete());
            }
        }
        // It calls TPM_init() within to indicate that a TPM2_Startup is required.
        // SAFETY: FFI call. No parameter, return value is checked.
        let result = unsafe { _plat__Signal_Reset() };
        if result != 0 {
            log::error!("_plat__Signal_Reset failed rc={}", result);
            return Err(SvsmReqError::incomplete());
        }
        self.is_powered_on = true;

        Ok(())
    }

    fn signal_nvon(&self) -> Result<(), SvsmReqError> {
        if !self.is_powered_on {
            return Err(SvsmReqError::invalid_request());
        }
        // SAFETY: FFI call. No Parameters or return values.
        unsafe { _plat__SetNvAvail() };

        Ok(())
    }
}

impl VtpmInterface for TcgTpm {
    fn run_selftest_cmd(&self) -> Result<(), SvsmReqError> {
        // TPM2_CC_SelfTest
        let selftest_cmd: &mut [u8] = &mut [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x43, 0x00,
        ];
        self.send_tpm_command(selftest_cmd, 0)?;

        Ok(())
    }

    fn run_startup_cmd(&self) -> Result<(), SvsmReqError> {
        // TPM2_CC_Startup
        let startup_cmd: &mut [u8] = &mut [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ];
        self.send_tpm_command(startup_cmd, 0)?;

        Ok(())
    }

    fn get_akpub(&mut self) -> Result<Vec<u8>, SvsmReqError> {
        if self.ak.is_none() {
            self.ak = Some(tss::create_ak(self, &PUBLIC_AREA_AK[..])?);
        }
        self.ak.clone().map(|ak| ak.akpub).ok_or_else(SvsmReqError::invalid_request)
    }

    fn get_ekpub(&mut self) -> Result<Vec<u8>, SvsmReqError> {
        if self.ek.is_none() {
            self.ek = Some(tss::create_ek(self, &DEFAULT_PUBLIC_AREA[..])?);
        }
        self.ek.clone().map(|ek| ek.ekpub).ok_or_else(SvsmReqError::invalid_request)
    }

    fn is_powered_on(&self) -> bool {
        self.is_powered_on
    }

    fn init(&mut self) -> Result<(), SvsmReqError> {
        // Initialize the TPM TCG following the same steps done in the Simulator and generate EK:
        //
        // 1. Manufacture it for the first time
        // 2. Make sure it does not fail if it is re-manufactured
        // 3. Teardown to indicate it needs to be manufactured
        // 4. Manufacture it for the first time
        // 5. Power it on indicating it requires startup. By default, OVMF will start
        //    and selftest it.
        // 6. Selftest it
        // 7. Start it up  on for next step
        // 8. Create RSA2004 EK and cache EKpub for VTPM service attestation requests
        //
        // Since we have already run TPM2_Startup here, when OVMF runs TPM2_Startup, it will
        // get back TPM_RC_INITIALIZE indicating that TPM2_Startup is not required. See,
        // https://github.com/tianocore/edk2/blob/master/SecurityPkg/Library/Tpm2CommandLib/Tpm2Startup.c#L75
        log::info!("VTPM: Init");
        // SAFETY: FFI call. Parameters and return values are checked.
        let mut rc = unsafe { _plat__NVEnable(VirtAddr::null().as_mut_ptr::<c_void>(), 0) };
        if rc != 0 {
            log::error!("_plat__NVEnable failed rc={}", rc);
            return Err(SvsmReqError::incomplete());
        }

        rc = self.manufacture(1)?;
        if rc != 0 {
            // SAFETY: FFI call. Parameter checked, no return value.
            unsafe { _plat__NVDisable(1 as *mut c_void, 0) };
            return Err(SvsmReqError::incomplete());
        }

        rc = self.manufacture(0)?;
        if rc != 1 {
            return Err(SvsmReqError::incomplete());
        }

        self.teardown()?;
        rc = self.manufacture(1)?;
        if rc != 0 {
            return Err(SvsmReqError::incomplete());
        }

        self.signal_poweron(false)?;
        self.signal_nvon()?;

        self.run_selftest_cmd()?;
        log::info!("run_startup_cmd");
        self.run_startup_cmd()?;

        // `tpm2_createek -c ek.handle -G rsa -u ek.pub`                                                                    
        self.ek = Some(tss::create_ek(self, &DEFAULT_PUBLIC_AREA[..])?);

        // `tpm2_createprimary -C o -g sha256 -G ecc:ecdsa -c ak.ctx -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|sign'`
        self.ak = Some(tss::create_ak(self, &PUBLIC_AREA_AK[..])?);

        // `tpm2_evictcontrol -C o -c ak.ctx $TPM_AK_HANDLE`
        // We can safely unwrap, as a None vaue would have already panicked.
        tss::evict_control(self, self.ak.clone().unwrap().akhandle, &TPM_AK_HANDLE.to_be_bytes()[..])?;
       
        // Verify the key is there with `tpm2_readpublic -c $TPM_AK_HANDLE -o ak.pub -f pem`

        log::info!("VTPM: AK created.");

        log::info!("VTPM: TPM 2.0 Reference Implementation initialized");

        Ok(())
    }
}

