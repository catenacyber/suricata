/* Copyright (C) 2022 Open Information Security Foundation
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

/**
 * \file
 *
 * \author Eric Leblond <el@stamus-networks.com>
 *
 */

#include "suricata-common.h"
#include "detect-engine-register.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"

#include "detect-smb-ntlmssp.h"
#include "rust.h"

#define BUFFER_NAME  "smb_ntlmssp_user"
#define KEYWORD_NAME "smb.ntlmssp_user"
#define KEYWORD_ID   DETECT_SMB_NTLMSSP_USER

static int g_smb_nltmssp_user_buffer_id = 0;

static int DetectSmbNtlmsspUserSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_smb_nltmssp_user_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SMB) < 0)
        return -1;

    return 0;
}

void DetectSmbNtlmsspUserRegister(void)
{
    sigmatch_table[KEYWORD_ID].name = KEYWORD_NAME;
    sigmatch_table[KEYWORD_ID].Setup = DetectSmbNtlmsspUserSetup;
    sigmatch_table[KEYWORD_ID].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
    sigmatch_table[KEYWORD_ID].desc = "sticky buffer to match on SMB ntlmssp user in session setup";

    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            SCSmbTxGetNtlmsspUser, ALPROTO_SMB, 1);

    DetectAppLayerInspectEngineRegister(BUFFER_NAME, ALPROTO_SMB, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, SCSmbTxGetNtlmsspUser);

    g_smb_nltmssp_user_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}

#undef BUFFER_NAME
#undef KEYWORD_NAME
#undef KEYWORD_ID

#define BUFFER_NAME  "smb_ntlmssp_domain"
#define KEYWORD_NAME "smb.ntlmssp_domain"
#define KEYWORD_ID   DETECT_SMB_NTLMSSP_DOMAIN

static int g_smb_nltmssp_domain_buffer_id = 0;

static int DetectSmbNtlmsspDomainSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_smb_nltmssp_domain_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SMB) < 0)
        return -1;

    return 0;
}

void DetectSmbNtlmsspDomainRegister(void)
{
    sigmatch_table[KEYWORD_ID].name = KEYWORD_NAME;
    sigmatch_table[KEYWORD_ID].Setup = DetectSmbNtlmsspDomainSetup;
    sigmatch_table[KEYWORD_ID].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
    sigmatch_table[KEYWORD_ID].desc =
            "sticky buffer to match on SMB ntlmssp domain in session setup";

    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            SCSmbTxGetNtlmsspDomain, ALPROTO_SMB, 1);

    DetectAppLayerInspectEngineRegister(BUFFER_NAME, ALPROTO_SMB, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, SCSmbTxGetNtlmsspDomain);

    g_smb_nltmssp_domain_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}
