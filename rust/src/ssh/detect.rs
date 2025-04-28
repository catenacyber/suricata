/* Copyright (C) 2020 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

use super::ssh::SSHTransaction;
use crate::core::DetectEngineThreadCtx;
use crate::direction::Direction;
use core::ffi::c_void;

#[no_mangle]
pub unsafe extern "C" fn SCSshTxGetProtocol(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, direction: u8, buf: *mut *const u8,
    len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SSHTransaction);
    match direction.into() {
        Direction::ToServer => {
            let m = &tx.cli_hdr.protover;
            if !m.is_empty() {
                *buf = m.as_ptr();
                *len = m.len() as u32;
                return true;
            }
        }
        Direction::ToClient => {
            let m = &tx.srv_hdr.protover;
            if !m.is_empty() {
                *buf = m.as_ptr();
                *len = m.len() as u32;
                return true;
            }
        }
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn SCSshTxGetSoftware(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, direction: u8, buf: *mut *const u8,
    len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SSHTransaction);
    match direction.into() {
        Direction::ToServer => {
            let m = &tx.cli_hdr.swver;
            if !m.is_empty() {
                *buf = m.as_ptr();
                *len = m.len() as u32;
                return true;
            }
        }
        Direction::ToClient => {
            let m = &tx.srv_hdr.swver;
            if !m.is_empty() {
                *buf = m.as_ptr();
                *len = m.len() as u32;
                return true;
            }
        }
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn SCSshTxGetHassh(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, direction: u8, buf: *mut *const u8,
    len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SSHTransaction);
    match direction.into() {
        Direction::ToServer => {
            let m = &tx.cli_hdr.hassh;
            if !m.is_empty() {
                *buf = m.as_ptr();
                *len = m.len() as u32;
                return true;
            }
        }
        Direction::ToClient => {
            let m = &tx.srv_hdr.hassh;
            if !m.is_empty() {
                *buf = m.as_ptr();
                *len = m.len() as u32;
                return true;
            }
        }
    }
    return false;
}

#[no_mangle]
pub unsafe extern "C" fn SCSshTxGetHasshString(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, direction: u8, buf: *mut *const u8,
    len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, SSHTransaction);
    match direction.into() {
        Direction::ToServer => {
            let m = &tx.cli_hdr.hassh_string;
            if !m.is_empty() {
                *buf = m.as_ptr();
                *len = m.len() as u32;
                return true;
            }
        }
        Direction::ToClient => {
            let m = &tx.srv_hdr.hassh_string;
            if !m.is_empty() {
                *buf = m.as_ptr();
                *len = m.len() as u32;
                return true;
            }
        }
    }
    return false;
}
