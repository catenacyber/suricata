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

use super::uint::{detect_parse_uint, DetectUintData};
use std::ffi::CStr;
use std::str::FromStr;

#[repr(C)]
#[derive(Debug, PartialEq)]
pub struct DetectVlanIdData {
    pub du16: DetectUintData<u16>,
    pub layer: i8,
}

pub fn detect_parse_vlan_id(s: &str) -> Option<DetectVlanIdData> {
    let parts: Vec<&str> = s.split(',').collect();
    let du16 = detect_parse_uint(parts[0]);
    if du16.is_err() {
        return None;
    }
    let du16 = du16.unwrap().1;
    if parts.len() > 2 {
        return None;
    }
    if du16.arg1 >= 0xFFF {
        // vlan id is encoded on 12 bits
        return None;
    }
    let layer = if parts.len() == 2 {
        i8::from_str(parts[1])
    } else {
        Ok(i8::MIN)
    };
    if layer.is_err() {
        return None;
    }
    let layer = layer.unwrap();
    if parts.len() == 2 && (layer < -3 || layer > 2) {
        return None;
    }
    return Some(DetectVlanIdData { du16, layer });
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_detect_parse_vlan_id() {
        assert_eq!(
            detect_parse_vlan_id("300").unwrap(),
            DetectVlanIdData {
                du16: 300,
                layer: 0
            }
        );
        assert_eq!(
            detect_parse_vlan_id("200,1").unwrap(),
            DetectVlanIdData {
                du16: 200,
                layer: 1
            }
        );
        assert!(detect_parse_vlan_id("200abc").is_none());
        assert!(detect_parse_vlan_id("4096").is_none());
        assert!(detect_parse_vlan_id("600,abc").is_none());
        assert!(detect_parse_vlan_id("600,100").is_none());
    }
}
