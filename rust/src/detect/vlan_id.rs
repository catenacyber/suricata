/* Copyright (C) 2024 Open Information Security Foundation
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

 use std::ffi::CStr;
 use std::str::FromStr;

#[repr(C)]
pub struct DetectVlanIdData {
    pub id: u16,
    pub layer:u8,
}

pub fn detect_parse_vlan_id(s: &str) -> Option<DetectVlanIdData> {
    let parts: Vec<&str> = s.split(',').collect();
    let id = u16::from_str(parts[0]);
    if id.is_err() {
        return None;
    }
    let id = id.unwrap();
    if parts.len() > 2 {
        return None;
    }
    let layer = if parts.len() == 2 {
         u8::from_str(parts[1])
    } else {
        Ok(0)
    };
    if layer.is_err() {
        return None;
    }
    let layer = layer.unwrap();
    return Some(DetectVlanIdData { id, layer });
}

#[no_mangle]
pub unsafe extern "C" fn rs_detect_vlan_id_parse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectVlanIdData {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Some(ctx) = detect_parse_vlan_id(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

