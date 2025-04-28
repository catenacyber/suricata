/* Copyright (C) 2025 Open Information Security Foundation
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
 * \author Philippe Antoine <pantoine@oisf.net>
 *
 */

#include "suricata-common.h"
#include "detect-smtp.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-helper.h"
#include "detect-parse.h"
#include "app-layer-smtp.h"
#include "rust.h"

static int g_smtp_helo_buffer_id = 0;
static int g_smtp_mail_from_buffer_id = 0;
static int g_smtp_rcpt_to_buffer_id = 0;

static int DetectSmtpHeloSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_smtp_helo_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SMTP) < 0)
        return -1;

    return 0;
}

static bool GetSmtpHeloData(DetectEngineThreadCtx *det_ctx, const void *txv,
        const uint8_t _flow_flags, const uint8_t **data, uint32_t *data_len)
{
    SMTPState *smtp_state = (SMTPState *)txv; // TODO state
    if (smtp_state) {
        if (smtp_state->helo != NULL) {
            *data = smtp_state->helo;
            *data_len = smtp_state->helo_len;
            return true;
        }
    }
    return false;
}

static int DetectSmtpMailFromSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_smtp_mail_from_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SMTP) < 0)
        return -1;

    return 0;
}

static bool GetSmtpMailFromData(DetectEngineThreadCtx *det_ctx, const void *txv,
        const uint8_t _flow_flags, const uint8_t **data, uint32_t *data_len)
{
    SMTPTransaction *tx = (SMTPTransaction *)txv;
    if (tx->mail_from == NULL)
        return false;
    *data = tx->mail_from;
    *data_len = tx->mail_from_len;
    return true;
}

static int DetectSmtpRcptToSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_smtp_rcpt_to_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SMTP) < 0)
        return -1;

    return 0;
}

static bool GetSmtpRcptToData(DetectEngineThreadCtx *_det_ctx, const void *txv, uint8_t _flow_flags,
        uint32_t idx, const uint8_t **buffer, uint32_t *buffer_len)
{
    SMTPTransaction *tx = (SMTPTransaction *)txv;
    if (TAILQ_EMPTY(&tx->rcpt_to_list)) {
        return false;
    }

    SMTPString *s;
    if (idx == 0) {
        s = TAILQ_FIRST(&tx->rcpt_to_list);
    } else {
        // TODO optimize ?
        s = TAILQ_FIRST(&tx->rcpt_to_list);
        for (uint32_t i = 0; i < idx; i++) {
            s = TAILQ_NEXT(s, next);
        }
    }
    if (s == NULL) {
        return false;
    }

    *buffer = s->str;
    *buffer_len = s->len;
    return true;
}

void SCDetectSMTPRegister(void)
{
    SCSigTableAppLiteElmt kw = { 0 };
    kw.name = "smtp.helo";
    kw.desc = "SMTP helo buffer";
    kw.url = "/rules/smtp-keywords.html#smtp-helo";
    kw.Setup = DetectSmtpHeloSetup;
    kw.flags = SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
    DetectHelperKeywordRegister(&kw);
    g_smtp_helo_buffer_id = DetectHelperBufferMpmRegister(
            "smtp.helo", "SMTP helo", ALPROTO_SMTP, STREAM_TOSERVER, GetSmtpHeloData);

    kw.name = "smtp.mail_from";
    kw.desc = "SMTP mail from buffer";
    kw.url = "/rules/smtp-keywords.html#smtp-mail-from";
    kw.Setup = DetectSmtpMailFromSetup;
    kw.flags = SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
    DetectHelperKeywordRegister(&kw);
    g_smtp_mail_from_buffer_id = DetectHelperBufferMpmRegister(
            "smtp.mail_from", "SMTP MAIL FROM", ALPROTO_SMTP, STREAM_TOSERVER, GetSmtpMailFromData);

    kw.name = "smtp.rcpt_to";
    kw.desc = "SMTP rcpt to buffer";
    kw.url = "/rules/smtp-keywords.html#smtp-rcpt-to";
    kw.Setup = DetectSmtpRcptToSetup;
    kw.flags = SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
    DetectHelperKeywordRegister(&kw);
    g_smtp_rcpt_to_buffer_id = DetectHelperMultiBufferMpmRegister(
            "smtp.rcpt_to", "SMTP RCPT TO", ALPROTO_SMTP, STREAM_TOSERVER, GetSmtpRcptToData);
}
