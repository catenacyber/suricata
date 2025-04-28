/* Copyright (C) 2007-2018 Open Information Security Foundation
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
 * \ingroup httplayer
 *
 * @{
 */


/**
 * \file
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Implements support for the http_user_agent keyword.
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-prefilter.h"
#include "detect-content.h"
#include "detect-pcre.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-spm.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-htp.h"
#include "stream-tcp.h"
#include "detect-http-ua.h"

static int DetectHttpUASetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectHttpUARegisterTests(void);
#endif
static int g_http_ua_buffer_id = 0;
static int DetectHttpUserAgentSetup(DetectEngineCtx *, Signature *, const char *);

static bool GetData(DetectEngineThreadCtx *det_ctx, const void *txv, const uint8_t flow_flags,
        const uint8_t **data, uint32_t *data_len)
{
    htp_tx_t *tx = (htp_tx_t *)txv;

    if (htp_tx_request_headers(tx) == NULL)
        return false;

    const htp_header_t *h = htp_tx_request_header(tx, "User-Agent");
    if (h == NULL || htp_header_value(h) == NULL) {
        SCLogDebug("HTTP UA header not present in this request");
        return false;
    }

    *data_len = htp_header_value_len(h);
    *data = htp_header_value_ptr(h);
    return true;
}

/**
 * \brief Registers the keyword handlers for the "http_user_agent" keyword.
 */
void DetectHttpUARegister(void)
{
    /* http_user_agent content modifier */
    sigmatch_table[DETECT_HTTP_USER_AGENT].name = "http_user_agent";
    sigmatch_table[DETECT_HTTP_USER_AGENT].desc =
            "content modifier to match only on the HTTP User-Agent header";
    sigmatch_table[DETECT_HTTP_USER_AGENT].url = "/rules/http-keywords.html#http-user-agent";
    sigmatch_table[DETECT_HTTP_USER_AGENT].Setup = DetectHttpUASetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_HTTP_USER_AGENT].RegisterTests = DetectHttpUARegisterTests;
#endif
    sigmatch_table[DETECT_HTTP_USER_AGENT].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_HTTP_USER_AGENT].flags |= SIGMATCH_INFO_CONTENT_MODIFIER;
    sigmatch_table[DETECT_HTTP_USER_AGENT].alternative = DETECT_HTTP_UA;

    /* http.user_agent sticky buffer */
    sigmatch_table[DETECT_HTTP_UA].name = "http.user_agent";
    sigmatch_table[DETECT_HTTP_UA].desc = "sticky buffer to match specifically and only on the HTTP User Agent buffer";
    sigmatch_table[DETECT_HTTP_UA].url = "/rules/http-keywords.html#http-user-agent";
    sigmatch_table[DETECT_HTTP_UA].Setup = DetectHttpUserAgentSetup;
    sigmatch_table[DETECT_HTTP_UA].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_HTTP_UA].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister("http_user_agent", ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_PROGRESS_HEADERS, DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister("http_user_agent", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetData, ALPROTO_HTTP1, HTP_REQUEST_PROGRESS_HEADERS);

    DetectAppLayerInspectEngineRegister("http_user_agent", ALPROTO_HTTP2, SIG_FLAG_TOSERVER,
            HTTP2StateDataClient, DetectEngineInspectBufferGeneric, SCHttp2TxGetUserAgent);

    DetectAppLayerMpmRegister("http_user_agent", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            SCHttp2TxGetUserAgent, ALPROTO_HTTP2, HTTP2StateDataClient);

    DetectBufferTypeSetDescriptionByName("http_user_agent",
            "http user agent");

    g_http_ua_buffer_id = DetectBufferTypeGetByName("http_user_agent");
}

/**
 * \brief The setup function for the http_user_agent keyword for a signature.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param s      Pointer to the signature for the current Signature being
 *               parsed from the rules.
 * \param m      Pointer to the head of the SigMatch for the current rule
 *               being parsed.
 * \param arg    Pointer to the string holding the keyword value.
 *
 * \retval  0 On success
 * \retval -1 On failure
 */
int DetectHttpUASetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    return DetectEngineContentModifierBufferSetup(
            de_ctx, s, arg, DETECT_HTTP_USER_AGENT, g_http_ua_buffer_id, ALPROTO_HTTP1);
}

/**
 * \brief this function setup the http.user_agent keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectHttpUserAgentSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_http_ua_buffer_id) < 0)
        return -1;
    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP) < 0)
        return -1;
    return 0;
}

#ifdef UNITTESTS
#include "tests/detect-http-user-agent.c"
#endif /* UNITTESTS */

/**
 * @}
 */
