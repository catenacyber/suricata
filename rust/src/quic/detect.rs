/* Copyright (C) 2021 Open Information Security Foundation
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

use crate::core::DetectEngineThreadCtx;
use crate::quic::quic::QuicTransaction;
use std::os::raw::c_void;
use std::ptr;

#[no_mangle]
pub unsafe extern "C" fn SCQuicTxGetUa(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flags: u8, buf: *mut *const u8,
    len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, QuicTransaction);
    if let Some(ua) = &tx.ua {
        *buf = ua.as_ptr();
        *len = ua.len() as u32;
        true
    } else {
        false
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCQuicTxGetSni(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flags: u8, buf: *mut *const u8,
    len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, QuicTransaction);
    if let Some(sni) = &tx.sni {
        *buf = sni.as_ptr();
        *len = sni.len() as u32;
        true
    } else {
        false
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCQuicTxGetJa3(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flags: u8, buf: *mut *const u8,
    len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, QuicTransaction);
    if let Some(ja3) = &tx.ja3 {
        *buf = ja3.as_ptr();
        *len = ja3.len() as u32;
        true
    } else {
        false
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCQuicTxGetJa4(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flags: u8, buf: *mut *const u8,
    len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, QuicTransaction);
    if let Some(ja4) = &tx.ja4 {
        *buf = ja4.as_ptr();
        *len = ja4.len() as u32;
        true
    } else {
        false
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCQuicTxGetVersion(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flags: u8, buf: *mut *const u8,
    len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, QuicTransaction);
    if tx.header.flags.is_long {
        let s = &tx.header.version_buf;
        *buf = s.as_ptr();
        *len = s.len() as u32;
        true
    } else {
        false
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCQuicTxGetCyuHash(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flags: u8, i: u32, buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, QuicTransaction);
    if (i as usize) < tx.cyu.len() {
        let cyu = &tx.cyu[i as usize];

        let p = &cyu.hash;

        *buffer = p.as_ptr();
        *buffer_len = p.len() as u32;

        true
    } else {
        *buffer = ptr::null();
        *buffer_len = 0;

        false
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCQuicTxGetCyuString(
    _de: *mut DetectEngineThreadCtx, tx: *const c_void, _flags: u8, i: u32, buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, QuicTransaction);
    if (i as usize) < tx.cyu.len() {
        let cyu = &tx.cyu[i as usize];

        let p = &cyu.string;

        *buffer = p.as_ptr();
        *buffer_len = p.len() as u32;
        true
    } else {
        *buffer = ptr::null();
        *buffer_len = 0;

        false
    }
}
