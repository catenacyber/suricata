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

#include "suricata-common.h"
#include "rust.h"
#include "detect-vlan-id.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-uint.h"
#include "detect-parse.h"
#include "util-byte.h"

static int DetectVlanIdMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    if (p->vlan_idx == 0) {
        return 0;
    }

    const DetectVlanIdData *vdata = (const DetectVlanIdData *)ctx;
    for (int i = 0; i < p->vlan_idx; i++) {
        if (p->vlan_id[i] == vdata->id && (vdata->layer == 0 || vdata->layer - 1 == i))
        {
            return 1;
        }
    }

    return 0;
}

static void DetectVlanIdFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectVlanIdData *data = ptr;
    SCFree(data);
}

static int DetectVlanIdSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectVlanIdData *vdata = rs_detect_vlan_id_parse(rawstr);
    SCLogInfo("vdata->id = [%i]", vdata->id);
    SCLogInfo("vdata->layer = [%i]", vdata->layer);
    if (vdata == NULL) {
        SCLogError("vlan id invalid %s", rawstr);
        return -1;
    }

    if (SigMatchAppendSMToList(
                de_ctx, s, DETECT_VLAN_ID, (SigMatchCtx *)vdata, DETECT_SM_LIST_MATCH) == NULL) {
        DetectVlanIdFree(de_ctx, vdata);
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

static void PrefilterPacketVlanIdMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    const PrefilterPacketHeaderCtx *ctx = pectx;

    for (int i = 0; i < p->vlan_idx; i++) {
        if (p->vlan_id[i] == ctx->v1.u16[0] && (ctx->v1.u8[0] == 0 || ctx->v1.u8[0] - 1 == i))
            PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void PrefilterPacketVlanIdSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectVlanIdData *a = smctx;
    v->u16[0] = a->id;
    v->u8[0] = a->layer;
}

static bool PrefilterPacketVlanIdCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectVlanIdData *a = smctx;
    if (v.u16[0] == a->id && v.u8[0] == a->layer)
        return true;
    return false;
}

static int PrefilterSetupVlanId(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_VLAN_ID, SIG_MASK_REQUIRE_FLOW,
            PrefilterPacketVlanIdSet, PrefilterPacketVlanIdCompare, PrefilterPacketVlanIdMatch);
}

static bool PrefilterVlanIdIsPrefilterable(const Signature *s)
{
    return PrefilterIsPrefilterableById(s, DETECT_VLAN_ID);
}

void DetectVlanIdRegister(void)
{
    sigmatch_table[DETECT_VLAN_ID].name = "vlan.id";
    sigmatch_table[DETECT_VLAN_ID].desc = "match vlan id";
    sigmatch_table[DETECT_VLAN_ID].url = "/rules/vlan-id.html";
    sigmatch_table[DETECT_VLAN_ID].Match = DetectVlanIdMatch;
    sigmatch_table[DETECT_VLAN_ID].Setup = DetectVlanIdSetup;
    sigmatch_table[DETECT_VLAN_ID].Free = DetectVlanIdFree;
    sigmatch_table[DETECT_VLAN_ID].SupportsPrefilter = PrefilterVlanIdIsPrefilterable;
    sigmatch_table[DETECT_VLAN_ID].SetupPrefilter = PrefilterSetupVlanId;
}
