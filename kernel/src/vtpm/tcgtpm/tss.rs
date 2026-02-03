// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025  Hewlett Packard Enterprise Development LP
// Copyright (c) Coconut-SVSM authors
//

// This module is an incomplete software stack for constructing commands to send to the TPM.
// It is not fully general for expressing all inputs to a command.

extern crate alloc;

use crate::protocols::errors::SvsmReqError;
use crate::vtpm::{
    tcgtpm::{TcgTpmSimulatorInterface, TPM_BUFFER_MAX_SIZE},
    SvsmVTpmError,
};
use alloc::vec::Vec;

pub const TPM_RC_SUCCESS: u32 = 0;

// Definitions from "Trusted Platform Module Library Part 4: Supporting Routines – Code,
// Family “2.0”, Level 00, Revision 01.38"
pub const TPM_ST_SESSIONS: u16 = 0x8002;
pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub const PLACEHOLDER_SIZE: u32 = 0;
const TPM_CC_CONTEXTSAVE: u32 = 0x00000162;
const TPM_CC_CREATEPRIMARY: u32 = 0x00000131;
const TPM_CC_CREATE: u32 = 0x00000153;
const TPM_RH_ENDORSEMENT: u32 = 0x4000000B;
const TPM_RH_OWNER: u32 = 0x40000001;
const TPM_CC_FLUSHCONTEXT: u32 = 0x00000165;
const TPM_CC_CONTEXTLOAD: u32 = 0x00000161;
const TPM_CC_EVICTCONTROL: u32 = 0x00000120;

#[derive(Debug, Clone)]
pub struct EK{
    pub ekpub: Vec<u8>,
    pub ekhandle: Vec<u8>
}

#[derive(Debug, Clone)]
pub struct AK{
    pub akpub: Vec<u8>,
    pub akhandle: Vec<u8>
}
// PREREQUISITE: CMD must be at least 10 bytes long.
// A TPM command result contains
//
// Byte offset | Size | Description
// ---
// 0x00        | 2    | u16 ST tag
// 0x02        | 4    | u32 response size
// 0x06        | 4    | u32 response code
fn tpm_cmd_rc(cmd: &[u8]) -> u32 {
    u32::from_be_bytes(cmd[6..10].try_into().unwrap())
}

fn extend_empty_auth(buf: &mut Vec<u8>) {
    // TPM_RS_PW(4) + nonce(2) + attributes(1) + pw(2)
    buf.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x09, // Size
        // TPM_RS_PW
        0x40, 0x00, 0x00, 0x09, // nonce == empty buffer
        0x00, 0x00, // session attributes = continueSession = 0x01
        0x01, // password = empty buffer
        0x00, 0x00,
    ]);
}

fn create_mtauth_ek_cmd(tpmt_public: &[u8]) -> Vec<u8> {
    let mut cmd = Vec::<u8>::with_capacity(TPM_BUFFER_MAX_SIZE);

    // TPM Command header
    cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&PLACEHOLDER_SIZE.to_be_bytes());
    cmd.extend_from_slice(&TPM_CC_CREATEPRIMARY.to_be_bytes());
    cmd.extend_from_slice(&TPM_RH_ENDORSEMENT.to_be_bytes());


    // Authorization block
    extend_empty_auth(&mut cmd);

    // inSensitive parameter
    //
    // TPM2B_SENSITIVE_CREATE structure is defined in
    // Table 132 — Definition of TPM2B_SENSITIVE_CREATE Structure,
    // Trusted Platform Module Library Part 2: Structures
    cmd.extend_from_slice(&[
        0x00, 0x04, // sensitive data size
        0x00, 0x00, 0x00, 0x00, // user auth
    ]);

    // inPublic parameter
    // parameters size
    cmd.extend_from_slice(&(tpmt_public.len() as u16).to_be_bytes());
    // parameters
    cmd.extend_from_slice(tpmt_public);

    cmd.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, // outsideInfo parameter
        0x00, 0x00, // pcr selection
    ]);

    // Update command size
    let command_size = cmd.len();
    cmd[2..6].copy_from_slice(&(command_size as u32).to_be_bytes());

    cmd.resize(TPM_BUFFER_MAX_SIZE, 0);
    cmd
}

fn create_mtauth_ak_cmd(tpmt_public: &[u8]) -> Vec<u8> {
    // tpm2_createprimary -C o -g sha256 -G ecc -c context.out -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign'
    let mut cmd = Vec::<u8>::with_capacity(TPM_BUFFER_MAX_SIZE);

    cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&PLACEHOLDER_SIZE.to_be_bytes());
    cmd.extend_from_slice(&TPM_CC_CREATEPRIMARY.to_be_bytes());
    cmd.extend_from_slice(&TPM_RH_OWNER.to_be_bytes()); // In the command I ran it was owner

    // Authorization block
    extend_empty_auth(&mut cmd);

    // inSensitive parameter
    //
    // TPM2B_SENSITIVE_CREATE structure is defined in
    // Table 132 — Definition of TPM2B_SENSITIVE_CREATE Structure,
    // Trusted Platform Module Library Part 2: Structures
    cmd.extend_from_slice(&[
        0x00, 0x04, // sensitive data size
        0x00, 0x00, 0x00, 0x00, // user auth
    ]);

   
    // inPublic parameter
    // parameters size
    cmd.extend_from_slice(&(tpmt_public.len() as u16).to_be_bytes());
    // parameters
    cmd.extend_from_slice(tpmt_public);

    cmd.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, // outsideInfo parameter
        0x00, 0x00, // pcr selection
    ]);

    // Update command size
    let command_size = cmd.len();
    cmd[2..6].copy_from_slice(&(command_size as u32).to_be_bytes());

    cmd.resize(TPM_BUFFER_MAX_SIZE, 0);
    cmd
}

fn create_flush_context_cmd(flush_handle: &[u8]) -> Vec<u8> {
    let mut cmd = Vec::<u8>::with_capacity(TPM_BUFFER_MAX_SIZE);

    cmd.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&PLACEHOLDER_SIZE.to_be_bytes());
    cmd.extend_from_slice(&TPM_CC_FLUSHCONTEXT.to_be_bytes());
    cmd.extend_from_slice(&flush_handle);

    // Update command size
    let command_size = cmd.len();
    cmd[2..6].copy_from_slice(&(command_size as u32).to_be_bytes());

    cmd.resize(TPM_BUFFER_MAX_SIZE, 0);
    cmd
}

fn create_evict_control_cmd(object_handle: Vec<u8>, persistent_handle: &[u8]) -> Vec<u8> {
    let mut cmd = Vec::<u8>::with_capacity(TPM_BUFFER_MAX_SIZE);

    cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&PLACEHOLDER_SIZE.to_be_bytes());
    cmd.extend_from_slice(&TPM_CC_EVICTCONTROL.to_be_bytes());
    cmd.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
    cmd.extend_from_slice(&object_handle);

    // Authorization block
    extend_empty_auth(&mut cmd);

    cmd.extend_from_slice(&persistent_handle);

    // Update command size
    let command_size = cmd.len();
    cmd[2..6].copy_from_slice(&(command_size as u32).to_be_bytes());

    cmd.resize(TPM_BUFFER_MAX_SIZE, 0);
    cmd
}

/// Sends `cmd` to `vtpm` and returns the interpretation of its error mode.
///
/// Arguments:
///
/// * `vtpm`: An implementation of [`TcgTpmSimulatorInterface`] to send `cmd` to.
/// * `cmd`: A command buffer.
/// * `set_len`: If true, sets the command length in the command header to `cmd.len()` before
///   sending the command.
///
/// Returns:
///
/// The command response on success, or an error.
pub fn checked_send<T: TcgTpmSimulatorInterface>(
    vtpm: &T,
    cmd: &mut [u8],
    set_len: bool,
) -> Result<Vec<u8>, SvsmVTpmError> {
    let command_size;
    if set_len {
        command_size = cmd.len();
        cmd[2..6].copy_from_slice(&(command_size as u32).to_be_bytes());
    } else {
        command_size = u32::from_be_bytes(cmd[2..6].try_into().unwrap()) as usize;
    }
    let response = vtpm
        .send_tpm_command(&cmd[..command_size], 0)
        .map_err(|_| SvsmVTpmError::ReqError(SvsmReqError::invalid_request()))?;
    let rc = tpm_cmd_rc(&response);
    if rc != TPM_RC_SUCCESS {
        log::info!("RC= {}", rc);
        return Err(SvsmVTpmError::CommandError(rc));
    }
    Ok(response)
}

/// Uses `vtpm` to create an a primary key on the endorsement hierarchy.
///
/// The key has no authorization policy.
///
/// Arguments:
///
/// * `vtpm`: An implementation of [`TcgTpmSimulatorInterface`] to send `cmd` to.
/// * `tpmt_public`: A marshaled TPMT_PUBLIC to use as the key creation template.
///
/// Returns:
///
/// A TPM_HANDLE of the object created. 
/// A TPMT_PUBLIC of the key created from the template.
pub fn create_ek<T: TcgTpmSimulatorInterface>(
    vtpm: &T,
    tpmt_public: &[u8],
) -> Result<EK, SvsmVTpmError> {
    log::info!("VTPM[create_ek]: Creating EK");
    let mut cmd = create_mtauth_ek_cmd(tpmt_public);
    let response = checked_send(vtpm, &mut cmd, /*set_len=*/ false)?;
    
    log::info!("VTPM[create_ek]: Done creating EK");
    // handle of type TPM_HT_TRANSIENT for created 
    // Primary Object
    let object_handle = response[10..14].to_vec();

    // Get size (UINT16) of TPMT_PUBLIC at offset 18.
    // Note this is output from the TPM, so its value is trusted.
    let size_of_tpmt_public = u16::from_be_bytes([response[18], response[19]]) as usize;
    let ekpub = response[20..(20 + size_of_tpmt_public)].to_vec();

    Ok(EK{ekpub: ekpub, ekhandle: object_handle})
}


/// Uses `vtpm` to create an a primary key on the endorsement hierarchy.
///
/// The key has no authorization policy.
///
/// Arguments:
///
/// * `vtpm`: An implementation of [`TcgTpmSimulatorInterface`] to send `cmd` to.
/// * `tpmt_public`: A marshaled TPMT_PUBLIC to use as the key creation template.
///
/// Returns:
///
/// A TPM_HANDLE of the object created. 
/// A TPMT_PUBLIC of the key created from the template.
pub fn create_ak<T: TcgTpmSimulatorInterface>(
    vtpm: &T,
    tpmt_public: &[u8],
) -> Result<AK, SvsmVTpmError> {
    log::info!("VTPM[create_ak]: Creating AK");
    let mut cmd = create_mtauth_ak_cmd(tpmt_public);
    let response = checked_send(vtpm, &mut cmd, /*set_len=*/ false)?;
    
    log::info!("VTPM[create_ak]: Done creating AK");

    // handle of type TPM_HT_TRANSIENT for created 
    // Primary Object
    let object_handle = response[10..14].to_vec();

    let size_of_tpmt_public = u16::from_be_bytes([response[18], response[19]]) as usize;
    let akpub = response[20..(20 + size_of_tpmt_public)].to_vec();

    Ok(AK{akpub: akpub, akhandle: object_handle})
    
}

pub fn evict_control<T: TcgTpmSimulatorInterface>(
    vtpm: &T,
    object_handle: Vec<u8>, 
    persistent_handle: &[u8],
) -> Result<(), SvsmVTpmError> {
    log::info!("VTPM[evict_control]: Evict control AK, persisting object at {:02X?} to {:02X?}",object_handle, persistent_handle);
    let mut cmd = create_evict_control_cmd(object_handle.clone(), persistent_handle);
    let _ = checked_send(vtpm, &mut cmd, /*set_len=*/ false)?;
    
    log::info!("VTPM[evict_control]: Done evict control AK");


    log::info!("VTPM[evict_control]: Flushing object_handle: {:02X?}.", object_handle);
    let mut cmd = create_flush_context_cmd(&object_handle);
    let _ = checked_send(vtpm, &mut cmd, /*set_len=*/ false)?;
    log::info!("VTPM[evict_control]: Done flushing object_handle: {:02X?}.", object_handle);


    Ok(())
    
}