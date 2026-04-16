// SPDX-License-Identifier: MIT

#include <stdlib.h>
#include <string.h>

#include <oqs/sig_{{ family }}.h>

{% for scheme in schemes -%}
#if defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['scheme'] }}) {%- if 'alias_scheme' in scheme %} || defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['alias_scheme'] }}){%- endif %}
{% if 'alias_scheme' in scheme %}
#if defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['scheme'] }})
{% endif %}
{%- set default_impl = scheme['metadata']['implementations'] | selectattr("name", "equalto", scheme['default_implementation']) | first -%}
OQS_SIG *OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_new(void) {

	OQS_SIG *sig = OQS_MEM_malloc(sizeof(OQS_SIG));
	if (sig == NULL) {
		return NULL;
	}
	memset(sig, 0, sizeof(OQS_SIG));
	sig->method_name = OQS_SIG_alg_{{ family }}_{{ scheme['scheme'] }};
	sig->alg_version = "{{ scheme['metadata']['implementations'][0]['version'] }}";

	sig->claimed_nist_level = {{ scheme['metadata']['claimed-nist-level'] }};
	sig->euf_cma = {{ scheme['metadata']['euf_cma'] }};
	sig->suf_cma = {{ scheme['metadata']['suf_cma'] }};
	{%- if 'api-with-context-string' in default_impl and default_impl['api-with-context-string'] %}
	sig->sig_with_ctx_support = true;
	{%- else %}
	sig->sig_with_ctx_support = false;
	{%- endif %}

	sig->length_public_key = OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_length_public_key;
	sig->length_secret_key = OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_length_secret_key;
	sig->length_signature = OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_length_signature;

#if defined(OQS_SIG_ENABLE_KEYGEN)
	sig->keypair = OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_keypair;
#endif
#if defined(OQS_SIG_ENABLE_SIGN)
	sig->sign = OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_sign;
	sig->sign_with_ctx_str = OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_sign_with_ctx_str;
#endif
#if defined(OQS_SIG_ENABLE_VERIFY)
	sig->verify = OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_verify;
	sig->verify_with_ctx_str = OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_verify_with_ctx_str;
#endif

	return sig;
}
{%- if 'alias_scheme' in scheme %}
#endif
{%- endif -%}

{%- if 'alias_scheme' in scheme %}

#if defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['alias_scheme'] }})
/** Alias */
OQS_SIG *OQS_SIG_{{ family }}_{{ scheme['alias_scheme'] }}_new(void) {

	OQS_SIG *sig = OQS_MEM_malloc(sizeof(OQS_SIG));
	if (sig == NULL) {
		return NULL;
	}
	memset(sig, 0, sizeof(OQS_SIG));
	sig->method_name = OQS_SIG_alg_{{ family }}_{{ scheme['alias_scheme'] }};
	sig->alg_version = "{{ scheme['metadata']['implementations'][0]['version'] }}";

	sig->claimed_nist_level = {{ scheme['metadata']['claimed-nist-level'] }};
	sig->euf_cma = {{ scheme['metadata']['euf_cma'] }};
	sig->suf_cma = {{ scheme['metadata']['suf_cma'] }};

	sig->length_public_key = OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_length_public_key;
	sig->length_secret_key = OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_length_secret_key;
	sig->length_signature = OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_length_signature;

#if defined(OQS_SIG_ENABLE_KEYGEN)
	sig->keypair = OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_keypair;
#endif
#if defined(OQS_SIG_ENABLE_SIGN)
	sig->sign = OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_sign;
#endif
#if defined(OQS_SIG_ENABLE_VERIFY)
	sig->verify = OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_verify;
#endif
    {%- if 'api-with-context-string' in default_impl and default_impl['api-with-context-string'] %}
#if defined(OQS_SIG_ENABLE_SIGN)
	sig->sign_with_ctx_str = OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_sign_with_ctx_str;
#endif
#if defined(OQS_SIG_ENABLE_VERIFY)
	sig->verify_with_ctx_str = OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_verify_with_ctx_str;
#endif
    {%- else %}
#if defined(OQS_SIG_ENABLE_SIGN)
	sig->sign_with_ctx_str = OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_sign_with_ctx_str;
#else
	sig->sign_with_ctx_str = NULL;
#endif
#if defined(OQS_SIG_ENABLE_VERIFY)
	sig->verify_with_ctx_str = OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_verify_with_ctx_str;
#else
	sig->verify_with_ctx_str = NULL;
#endif
    {%- endif %}

	return sig;
}
#endif
{%- endif -%}

    {%- for impl in scheme['metadata']['implementations'] if impl['name'] == scheme['default_implementation'] %}

        {%- if impl['signature_keypair'] %}
           {%- set cleankeypair = scheme['metadata'].update({'default_keypair_signature': impl['signature_keypair']}) -%}
        {%- else %}
           {%- set cleankeypair = scheme['metadata'].update({'default_keypair_signature': "PQCLEAN_"+scheme['pqclean_scheme_c']|upper+"_"+scheme['default_implementation']|upper+"_crypto_sign_keypair"}) -%}
        {%- endif %}

extern int {{ scheme['metadata']['default_keypair_signature'] }}(uint8_t *pk, uint8_t *sk);

        {%- if impl['signature_signature'] %}
           {%- set cleansignature = scheme['metadata'].update({'default_signature_signature': impl['signature_signature']}) -%}
        {%- else %}
           {%- set cleansignature = scheme['metadata'].update({'default_signature_signature': "PQCLEAN_"+scheme['pqclean_scheme_c']|upper+"_"+scheme['default_implementation']|upper+"_crypto_sign_signature"}) -%}
        {%- endif %}
{%- if 'api-with-context-string' in impl and impl['api-with-context-string'] %}
extern int {{ scheme['metadata']['default_signature_signature'] }}(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
{%- else %}
extern int {{ scheme['metadata']['default_signature_signature'] }}(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
{%- endif %}

        {%- if impl['signature_verify'] %}
           {%- set cleanverify = scheme['metadata'].update({'default_verify_signature': impl['signature_verify']}) -%}
        {%- else %}
           {%- set cleanverify = scheme['metadata'].update({'default_verify_signature': "PQCLEAN_"+scheme['pqclean_scheme_c']|upper+"_"+scheme['default_implementation']|upper+"_crypto_sign_verify"}) -%}
        {%- endif %}
{%- if 'api-with-context-string' in impl and impl['api-with-context-string'] %}
extern int {{ scheme['metadata']['default_verify_signature']  }}(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);
{%- else %}
extern int {{ scheme['metadata']['default_verify_signature']  }}(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
{%- endif %}

    {%- endfor %}

    {%- for impl in scheme['metadata']['implementations'] if impl['name'] != scheme['default_implementation'] %}

#if defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['scheme'] }}_{{ impl['name'] }}) {%- if 'alias_scheme' in scheme %} || defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['alias_scheme'] }}_{{ impl['name'] }}){%- endif %}
        {%- if impl['signature_keypair'] %}
extern int {{ impl['signature_keypair'] }}(uint8_t *pk, uint8_t *sk);
        {%- else %}
extern int PQCLEAN_{{ scheme['pqclean_scheme_c']|upper }}_{{ impl['name']|upper }}_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
        {%- endif %}

        {%- if impl['signature_signature'] %}
{%- if 'api-with-context-string' in impl and impl['api-with-context-string'] %}
extern int {{ impl['signature_signature'] }}(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
{%- else %}
extern int {{ impl['signature_signature'] }}(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
{%- endif %}
        {%- else %}
extern int PQCLEAN_{{ scheme['pqclean_scheme_c']|upper }}_{{ impl['name']|upper }}_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
        {%- endif %}

        {%- if impl['signature_verify'] %}
{%- if 'api-with-context-string' in impl and impl['api-with-context-string'] %}
extern int {{ impl['signature_verify'] }}(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);
{%- else %}
extern int {{ impl['signature_verify'] }}(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
{%- endif %}
        {%- else %}
extern int PQCLEAN_{{ scheme['pqclean_scheme_c']|upper }}_{{ impl['name']|upper }}_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
        {%- endif %}
#endif
    {%- endfor %}

#if defined(OQS_SIG_ENABLE_KEYGEN)
OQS_API OQS_STATUS OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_keypair(uint8_t *public_key, uint8_t *secret_key) {
    {%- for impl in scheme['metadata']['implementations'] if impl['name'] != scheme['default_implementation'] %}
    {%- if loop.first %}
#if defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['scheme'] }}_{{ impl['name'] }}) {%- if 'alias_scheme' in scheme %} || defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['alias_scheme'] }}_{{ impl['name'] }}){%- endif %}
    {%- else %}
#elif defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['scheme'] }}_{{ impl['name'] }}) {%- if 'alias_scheme' in scheme %} || defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['alias_scheme'] }}_{{ impl['name'] }}){%- endif %}
    {%- endif %}
    {%- if impl.get('required_flags', false) %}
#if defined(OQS_DIST_BUILD)
	if ({%- for flag in impl['required_flags'] -%}OQS_CPU_has_extension(OQS_CPU_EXT_{{ flag|upper }}){%- if not loop.last %} && {% endif -%}{%- endfor -%}) {
#endif /* OQS_DIST_BUILD */
    {%- endif %}
           {%- if impl['signature_keypair'] %}
	{% if impl.get('required_flags', false) %}	{% endif %}return (OQS_STATUS) {{ impl['signature_keypair'] }}(public_key, secret_key);
           {%- else %}
	{% if impl.get('required_flags', false) %}	{% endif %}return (OQS_STATUS) PQCLEAN_{{ scheme['pqclean_scheme_c']|upper }}_{{ impl['name']|upper }}_crypto_sign_keypair(public_key, secret_key);
           {%- endif %}
    {%- if impl.get('required_flags', false) %}
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) {{ scheme['metadata']['default_keypair_signature'] }}(public_key, secret_key);
	}
#endif /* OQS_DIST_BUILD */
    {%- endif %}
    {%- endfor %}
    {%- if scheme['metadata']['implementations']|rejectattr('name', 'equalto', scheme['default_implementation'])|list %}
#else
    {%- endif %}
	return (OQS_STATUS) {{ scheme['metadata']['default_keypair_signature'] }}(public_key, secret_key);
    {%- if scheme['metadata']['implementations']|rejectattr('name', 'equalto', scheme['default_implementation'])|list %}
#endif
    {%- endif %}
}
#else /* !OQS_SIG_ENABLE_KEYGEN */
OQS_API OQS_STATUS OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_keypair(uint8_t *public_key, uint8_t *secret_key) {
	(void)public_key;
	(void)secret_key;
	return OQS_ERROR;
}
#endif /* OQS_SIG_ENABLE_KEYGEN */

#if defined(OQS_SIG_ENABLE_SIGN)
OQS_API OQS_STATUS OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
    {%- for impl in scheme['metadata']['implementations'] if impl['name'] != scheme['default_implementation'] %}
    {%- if loop.first %}
#if defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['scheme'] }}_{{ impl['name'] }}) {%- if 'alias_scheme' in scheme %} || defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['alias_scheme'] }}_{{ impl['name'] }}){%- endif %}
    {%- else %}
#elif defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['scheme'] }}_{{ impl['name'] }}) {%- if 'alias_scheme' in scheme %} || defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['alias_scheme'] }}_{{ impl['name'] }}){%- endif %}
    {%- endif %}
    {%- if impl.get('required_flags', false) %}
#if defined(OQS_DIST_BUILD)
	if ({%- for flag in impl['required_flags'] -%}OQS_CPU_has_extension(OQS_CPU_EXT_{{ flag|upper }}){%- if not loop.last %} && {% endif -%}{%- endfor -%}) {
#endif /* OQS_DIST_BUILD */
    {%- endif %}
           {%- if impl['signature_signature'] %}
           {%- if 'api-with-context-string' in impl and impl['api-with-context-string'] %}
	{% if impl.get('required_flags', false) %}	{% endif %}return (OQS_STATUS) {{ impl['signature_signature'] }}(signature, signature_len, message, message_len, NULL, 0, secret_key);
           {%- else %}
	{% if impl.get('required_flags', false) %}	{% endif %}return (OQS_STATUS) {{ impl['signature_signature'] }}(signature, signature_len, message, message_len, secret_key);
           {%- endif %}
           {%- else %}
	{% if impl.get('required_flags', false) %}	{% endif %}return (OQS_STATUS) PQCLEAN_{{ scheme['pqclean_scheme_c']|upper }}_{{ impl['name']|upper }}_crypto_sign_signature(signature, signature_len, message, message_len, secret_key);
           {%- endif %}
    {%- if impl.get('required_flags', false) %}
#if defined(OQS_DIST_BUILD)
	} else {
        {%- if 'api-with-context-string' in impl and impl['api-with-context-string'] %}
		return (OQS_STATUS) {{ scheme['metadata']['default_signature_signature'] }}(signature, signature_len, message, message_len, NULL, 0, secret_key);
        {%- else %}
		return (OQS_STATUS) {{ scheme['metadata']['default_signature_signature'] }}(signature, signature_len, message, message_len, secret_key);
        {%- endif %}
	}
#endif /* OQS_DIST_BUILD */
    {%- endif %}
    {%- endfor %}
    {%- if scheme['metadata']['implementations']|rejectattr('name', 'equalto', scheme['default_implementation'])|list %}
#else
    {%- endif %}
    {%- set default_impl = scheme['metadata']['implementations'] | selectattr("name", "equalto", scheme['default_implementation']) | first -%}
    {%- if 'api-with-context-string' in default_impl and default_impl['api-with-context-string'] %}
	return (OQS_STATUS) {{ scheme['metadata']['default_signature_signature'] }}(signature, signature_len, message, message_len, NULL, 0, secret_key);
    {%- else %}
	return (OQS_STATUS) {{ scheme['metadata']['default_signature_signature'] }}(signature, signature_len, message, message_len, secret_key);
    {%- endif %}
    {%- if scheme['metadata']['implementations']|rejectattr('name', 'equalto', scheme['default_implementation'])|list %}
#endif
    {%- endif %}
}
#else /* !OQS_SIG_ENABLE_SIGN */
OQS_API OQS_STATUS OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	(void)signature;
	(void)signature_len;
	(void)message;
	(void)message_len;
	(void)secret_key;
	return OQS_ERROR;
}
#endif /* OQS_SIG_ENABLE_SIGN */

#if defined(OQS_SIG_ENABLE_VERIFY)
OQS_API OQS_STATUS OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
    {%- for impl in scheme['metadata']['implementations'] if impl['name'] != scheme['default_implementation'] %}
    {%- if loop.first %}
#if defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['scheme'] }}_{{ impl['name'] }}) {%- if 'alias_scheme' in scheme %} || defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['alias_scheme'] }}_{{ impl['name'] }}){%- endif %}
    {%- else %}
#elif defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['scheme'] }}_{{ impl['name'] }}) {%- if 'alias_scheme' in scheme %} || defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['alias_scheme'] }}_{{ impl['name'] }}){%- endif %}
    {%- endif %}
    {%- if impl.get('required_flags', false) %}
#if defined(OQS_DIST_BUILD)
	if ({%- for flag in impl['required_flags'] -%}OQS_CPU_has_extension(OQS_CPU_EXT_{{ flag|upper }}){%- if not loop.last %} && {% endif -%}{%- endfor -%}) {
#endif /* OQS_DIST_BUILD */
    {%- endif %}
           {%- if impl['signature_verify'] %}
           {%- if 'api-with-context-string' in impl and impl['api-with-context-string'] %}
	{% if impl.get('required_flags', false) %}	{% endif %}return (OQS_STATUS) {{ impl['signature_verify'] }}(signature, signature_len, message, message_len, NULL, 0, public_key);
           {%- else %}
	{% if impl.get('required_flags', false) %}	{% endif %}return (OQS_STATUS) {{ impl['signature_verify'] }}(signature, signature_len, message, message_len, public_key);
           {%- endif %}
           {%- else %}
	{% if impl.get('required_flags', false) %}	{% endif %}return (OQS_STATUS) PQCLEAN_{{ scheme['pqclean_scheme_c']|upper }}_{{ impl['name']|upper }}_crypto_sign_verify(signature, signature_len, message, message_len, public_key);
           {%- endif %}
    {%- if impl.get('required_flags', false) %}
#if defined(OQS_DIST_BUILD)
	} else {
        {%- if 'api-with-context-string' in impl and impl['api-with-context-string'] %}
		return (OQS_STATUS) {{ scheme['metadata']['default_verify_signature'] }}(signature, signature_len, message, message_len, NULL, 0, public_key);
        {%- else %}
		return (OQS_STATUS) {{ scheme['metadata']['default_verify_signature'] }}(signature, signature_len, message, message_len, public_key);
        {%- endif %}
	}
#endif /* OQS_DIST_BUILD */
    {%- endif %}
    {%- endfor %}
    {%- if scheme['metadata']['implementations']|rejectattr('name', 'equalto', scheme['default_implementation'])|list %}
#else
    {%- endif %}
    {%- set default_impl = scheme['metadata']['implementations'] | selectattr("name", "equalto", scheme['default_implementation']) | first -%}
    {%- if 'api-with-context-string' in default_impl and default_impl['api-with-context-string'] %}
	return (OQS_STATUS) {{ scheme['metadata']['default_verify_signature'] }}(signature, signature_len, message, message_len, NULL, 0, public_key);
    {%- else %}
	return (OQS_STATUS) {{ scheme['metadata']['default_verify_signature'] }}(signature, signature_len, message, message_len, public_key);
    {%- endif %}
    {%- if scheme['metadata']['implementations']|rejectattr('name', 'equalto', scheme['default_implementation'])|list %}
#endif
    {%- endif %}
}
#else /* !OQS_SIG_ENABLE_VERIFY */
OQS_API OQS_STATUS OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	(void)message;
	(void)message_len;
	(void)signature;
	(void)signature_len;
	(void)public_key;
	return OQS_ERROR;
}
#endif /* OQS_SIG_ENABLE_VERIFY */

{%- set default_impl = scheme['metadata']['implementations'] | selectattr("name", "equalto", scheme['default_implementation']) | first %}
{%- if 'api-with-context-string' in default_impl and default_impl['api-with-context-string'] %}
#if defined(OQS_SIG_ENABLE_SIGN)
OQS_API OQS_STATUS OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
    {%- for impl in scheme['metadata']['implementations'] if impl['name'] != scheme['default_implementation'] %}
    {%- if loop.first %}
#if defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['scheme'] }}_{{ impl['name'] }}) {%- if 'alias_scheme' in scheme %} || defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['alias_scheme'] }}_{{ impl['name'] }}){%- endif %}
    {%- else %}
#elif defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['scheme'] }}_{{ impl['name'] }}) {%- if 'alias_scheme' in scheme %} || defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['alias_scheme'] }}_{{ impl['name'] }}){%- endif %}
    {%- endif %}
    {%- if impl.get('required_flags', false) %}
#if defined(OQS_DIST_BUILD)
	if ({%- for flag in impl['required_flags'] -%}OQS_CPU_has_extension(OQS_CPU_EXT_{{ flag|upper }}){%- if not loop.last %} && {% endif -%}{%- endfor -%}) {
#endif /* OQS_DIST_BUILD */
    {%- endif %}
           {%- if impl['signature_signature'] %}
	{% if impl.get('required_flags', false) %}	{% endif %}return (OQS_STATUS) {{ impl['signature_signature'] }}(signature, signature_len, message, message_len, ctx_str, ctx_str_len, secret_key);
           {%- else %}
	{% if impl.get('required_flags', false) %}	{% endif %}return (OQS_STATUS) PQCLEAN_{{ scheme['pqclean_scheme_c']|upper }}_{{ impl['name']|upper }}_crypto_sign_signature(signature, signature_len, message, message_len, ctx_str, ctx_str_len, secret_key);
           {%- endif %}
    {%- if impl.get('required_flags', false) %}
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) {{ scheme['metadata']['default_signature_signature'] }}(signature, signature_len, message, message_len, ctx_str, ctx_str_len, secret_key);
	}
#endif /* OQS_DIST_BUILD */
    {%- endif %}
    {%- endfor %}
    {%- if scheme['metadata']['implementations']|rejectattr('name', 'equalto', scheme['default_implementation'])|list %}
#else
    {%- endif %}
    {%- set default_impl = scheme['metadata']['implementations'] | selectattr("name", "equalto", scheme['default_implementation']) | first %}
	return (OQS_STATUS) {{ scheme['metadata']['default_signature_signature'] }}(signature, signature_len, message, message_len, ctx_str, ctx_str_len, secret_key);
    {%- if scheme['metadata']['implementations']|rejectattr('name', 'equalto', scheme['default_implementation'])|list %}
#endif
    {%- endif %}
}
#else /* !OQS_SIG_ENABLE_SIGN */
OQS_API OQS_STATUS OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
	(void)signature;
	(void)signature_len;
	(void)message;
	(void)message_len;
	(void)ctx_str;
	(void)ctx_str_len;
	(void)secret_key;
	return OQS_ERROR;
}
#endif /* OQS_SIG_ENABLE_SIGN */

#if defined(OQS_SIG_ENABLE_VERIFY)
OQS_API OQS_STATUS OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
    {%- for impl in scheme['metadata']['implementations'] if impl['name'] != scheme['default_implementation'] %}
    {%- if loop.first %}
#if defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['scheme'] }}_{{ impl['name'] }}) {%- if 'alias_scheme' in scheme %} || defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['alias_scheme'] }}_{{ impl['name'] }}){%- endif %}
    {%- else %}
#elif defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['scheme'] }}_{{ impl['name'] }}) {%- if 'alias_scheme' in scheme %} || defined(OQS_ENABLE_SIG_{{ family }}_{{ scheme['alias_scheme'] }}_{{ impl['name'] }}){%- endif %}
    {%- endif %}
    {%- if impl.get('required_flags', false) %}
#if defined(OQS_DIST_BUILD)
	if ({%- for flag in impl['required_flags'] -%}OQS_CPU_has_extension(OQS_CPU_EXT_{{ flag|upper }}){%- if not loop.last %} && {% endif -%}{%- endfor -%}) {
#endif /* OQS_DIST_BUILD */
    {%- endif %}
           {%- if impl['signature_verify'] %}
	{% if impl.get('required_flags', false) %}	{% endif %}return (OQS_STATUS) {{ impl['signature_verify'] }}(signature, signature_len, message, message_len, ctx_str, ctx_str_len, public_key);
           {%- else %}
	{% if impl.get('required_flags', false) %}	{% endif %}return (OQS_STATUS) PQCLEAN_{{ scheme['pqclean_scheme_c']|upper }}_{{ impl['name']|upper }}_crypto_sign_verify(signature, signature_len, message, message_len, ctx_str, ctx_str_len, public_key);
           {%- endif %}
    {%- if impl.get('required_flags', false) %}
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) {{ scheme['metadata']['default_verify_signature'] }}(signature, signature_len, message, message_len, ctx_str, ctx_str_len, public_key);
	}
#endif /* OQS_DIST_BUILD */
    {%- endif %}
    {%- endfor %}
    {%- if scheme['metadata']['implementations']|rejectattr('name', 'equalto', scheme['default_implementation'])|list %}
#else
    {%- endif %}
    {%- set default_impl = scheme['metadata']['implementations'] | selectattr("name", "equalto", scheme['default_implementation']) | first %}
	return (OQS_STATUS) {{ scheme['metadata']['default_verify_signature'] }}(signature, signature_len, message, message_len, ctx_str, ctx_str_len, public_key);
    {%- if scheme['metadata']['implementations']|rejectattr('name', 'equalto', scheme['default_implementation'])|list %}
#endif
    {%- endif %}
}
#else /* !OQS_SIG_ENABLE_VERIFY */
OQS_API OQS_STATUS OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
	(void)message;
	(void)message_len;
	(void)signature;
	(void)signature_len;
	(void)ctx_str;
	(void)ctx_str_len;
	(void)public_key;
	return OQS_ERROR;
}
#endif /* OQS_SIG_ENABLE_VERIFY */
{%- else %}

#if defined(OQS_SIG_ENABLE_SIGN)
OQS_API OQS_STATUS OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
	if (ctx_str == NULL && ctx_str_len == 0) {
		return OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_sign(signature, signature_len, message, message_len, secret_key);
	} else {
		return OQS_ERROR;
	}
}
#else /* !OQS_SIG_ENABLE_SIGN */
OQS_API OQS_STATUS OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
	(void)signature;
	(void)signature_len;
	(void)message;
	(void)message_len;
	(void)ctx_str;
	(void)ctx_str_len;
	(void)secret_key;
	return OQS_ERROR;
}
#endif /* OQS_SIG_ENABLE_SIGN */

#if defined(OQS_SIG_ENABLE_VERIFY)
OQS_API OQS_STATUS OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
	if (ctx_str == NULL && ctx_str_len == 0) {
		return OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_verify(message, message_len, signature, signature_len, public_key);
	} else {
		return OQS_ERROR;
	}
}
#else /* !OQS_SIG_ENABLE_VERIFY */
OQS_API OQS_STATUS OQS_SIG_{{ family }}_{{ scheme['scheme'] }}_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
	(void)message;
	(void)message_len;
	(void)signature;
	(void)signature_len;
	(void)ctx_str;
	(void)ctx_str_len;
	(void)public_key;
	return OQS_ERROR;
}
#endif /* OQS_SIG_ENABLE_VERIFY */
{%- endif %}
#endif
{% endfor -%}
