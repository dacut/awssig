// Package awssig provides AWS API request signatures verification routines.
//
// This is essentially the server-side complement of
// github.com/aws/aws-sdk-go/aws/signer/v4
// (https://docs.aws.amazon.com/sdk-for-go/api/aws/signer/v4/).
//
// This implements the AWS SigV4 and SigV4S3 algorithms
// (http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html and
// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html)
package awssig

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dacut/awssig/timeutil"
	"github.com/palantir/stacktrace"
	"golang.org/x/text/encoding/htmlindex"
)

const (
	iso8601CompactFormat             = "20060102T150405Z"
	keyAWS4                          = "AWS4"
	keyApplicationXWWWFormURLEncoded = "application/x-www-form-urlencoded"
	keyAuthorization                 = "authorization"
	keyAWS4HMACSHA256                = "AWS4-HMAC-SHA256"
	keyAWS4Request                   = "aws4_request"
	keyCharset                       = "charset"
	keyContentType                   = "content-type"
	keyCredential                    = "Credential"
	keyDate                          = "date"
	keySignature                     = "Signature"
	keySignedHeaders                 = "SignedHeaders"
	keyXAmzCredential                = "X-Amz-Credential"
	keyXAmzDate                      = "X-Amz-Date"
	keyXAmzDateLower                 = "x-amz-date"
	keyXAmzSecurityToken             = "x-Amz-Security-Token"
	keyXAmzSecurityTokenLower        = "x-amz-security-token"
	keyXAmzSignature                 = "X-Amz-Signature"
	keyXAmzSignedHeaders             = "X-Amz-SignedHeaders"
	msgFailedToGetCReqBuf            = "Failed to get canonical request: Failed while writing to internal buffer"
	msgFailedToGetSTSBuf             = "Failed to get string to sign: Failed while writing to internal buffer"
	sha256Empty                      = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

var multislash = regexp.MustCompile("//+")
var multispace = regexp.MustCompile("  +")

// Request is a data structure containing the elements of the request
// (some client-supplied, some service-supplied) involved in the SigV4
// verification process.
type Request struct {
	// The request method (GET, PUT, POST). Client supplied.
	RequestMethod string

	// The URI path being accessed. This must be an absolute path starting
	// with "/".  Client supplied
	URIPath string

	// Query string portion of the URI. Client suppplied
	QueryString string

	// The HTTP headers and their values sent with the request. The header keys
	// must be lower-cased. Client supplied.
	Headers map[string][]string

	// The request body (if any). Client supplied.
	Body string

	// The region the request was sent to. Service supplied.
	Region string

	// The service being accessed. Service supplied.
	Service string
}

// SignedHeader incorporates a header name and its associated value.
type SignedHeader struct {
	// The name of the header
	Name string

	// The associated value of the header
	Value string
}

// GetContentTypeAndCharset returns the content type and character set used
// in the request.
//
// If the content-type header is not included in the request, an empty
// contentType and charset are returned.
//
// If multiple content-type values were specified, an error is returned.
func (r *Request) GetContentTypeAndCharset() (contentType string, charset string, err error) {
	contentTypeList, ok := r.Headers[keyContentType]

	if !ok || len(contentTypeList) == 0 {
		return
	}

	if len(contentTypeList) > 1 {
		return "", "", stacktrace.NewError(
			"Multiple values for Content-Type header: %#v", contentTypeList)
	}

	parts := strings.Split(contentTypeList[0], ";")
	contentType = strings.TrimSpace(parts[0])
	charset = "utf-8"

	for _, paramString := range parts {
		paramString = strings.TrimSpace(paramString)
		paramParts := strings.SplitN(paramString, "=", 2)
		if len(paramParts) == 2 {
			paramName := strings.ToLower(strings.TrimSpace(paramParts[0]))
			paramValue := strings.TrimSpace(paramParts[1])

			if paramName == keyCharset {
				charset = paramValue
				break
			}
		}
	}

	return
}

// GetCanonicalizedURIPath returns the canonicalized URI path from the request.
//
// If the URI path cannot be canonicalized due to
// invalid relative path components or invalid percent encoding, an error
// is returned.
func (r *Request) GetCanonicalizedURIPath() (string, error) {
	return CanonicalizeURIPath(r.URIPath)
}

// GetCanonicalQueryString returns the canonical query string from the query
// parameters.
//
// This takes the query string from the request, ordering multiple values for
// each key (e.g., "x=foo&x=bar" becomes "x=bar&x=foo"), and orders the keys
// ("y=a&x=b" becomes "x=a&y=b").
//
// If the body is of type "application/x-www-form-urlencoded", it is included
// as part of the query string.
//
// An error is returned if the query string contains an invalid percent
// encoding or the body is of type "application/x-www-form-urlencoded" and
// not a supported character set encoding.
func (r *Request) GetCanonicalQueryString() (string, error) {
	results := make([]string, 0)

	qpmap, err := NormalizeQueryParameters(r.QueryString)
	if err != nil {
		return "", stacktrace.Propagate(
			err, "Unable to canonicalize query string: %#v", r.QueryString)
	}

	for key, values := range qpmap {
		if key != keyXAmzSignature {
			for _, value := range values {
				results = append(results, key+"="+value)
			}
		}
	}

	if contentType, charset, err := r.GetContentTypeAndCharset(); err != nil {
		return "", stacktrace.Propagate(
			err, "Unable to canonicalize query string: unable to get "+
				"content-type header")
	} else if contentType == keyApplicationXWWWFormURLEncoded {
		encoding, err := htmlindex.Get(charset)
		if err != nil {
			return "", stacktrace.Propagate(
				err, "Unable to canonicalize query string: unable to get "+
					"encoder for charset %#v to decode "+
					"application/x-www-form-urlencoded body", charset)
		}

		decoder := encoding.NewDecoder()
		utf8Body, err := decoder.String(r.Body)
		if err != nil {
			return "", stacktrace.Propagate(
				err, "Unable to canonicalize query string: unable to "+
					"decode application/x-www-form-urlencoded body using "+
					"charset %#v", charset)
		}

		qpmap, err := NormalizeQueryParameters(utf8Body)
		if err != nil {
			return "", stacktrace.Propagate(
				err, "Unable to canonicalize query string from "+
					"application/x-www-form-urlencoded body: %#v",
				utf8Body)
		}

		for key, values := range qpmap {
			if key != keyXAmzSignature {
				for _, value := range values {
					results = append(results, key+"="+value)
				}
			}
		}
	}

	sort.Strings(results)
	return strings.Join(results, "&"), nil
}

// GetAuthorizationHeaderParameters returns the parameters from the
// authorization header (only). If there is not exactly one authorization
// header present using the AWS4-HMAC-SHA256 algorithm, an error is returned.
func (r *Request) GetAuthorizationHeaderParameters() (map[string]string, error) {
	authHeaders, ok := r.Headers[keyAuthorization]

	if !ok || len(authHeaders) == 0 {
		return nil, stacktrace.NewError("authorization header is not present")
	}

	var sigv4Header string

	for _, authHeader := range authHeaders {
		if strings.HasPrefix(authHeader, keyAWS4HMACSHA256+" ") {
			if sigv4Header != "" {
				return nil, stacktrace.NewError(
					"Multiple %s authorization headers present",
					keyAWS4HMACSHA256)
			}

			sigv4Header = authHeader
		}
	}

	if sigv4Header == "" {
		return nil, stacktrace.NewError(
			"No %s authorization headers present", keyAWS4HMACSHA256)
	}

	result := make(map[string]string)
	authValues := strings.Split(sigv4Header[len(keyAWS4HMACSHA256)+1:], ",")

	for _, parameter := range authValues {
		parameter = strings.TrimSpace(parameter)
		parameterParts := strings.SplitN(parameter, ",", 2)
		if len(parameterParts) != 2 {
			return nil, stacktrace.NewError(
				"Invalid authorization header: missing '=' in "+
					"parameter: %#v", parameter)
		}

		key := parameterParts[0]
		value := parameterParts[1]

		if _, exists := result[key]; exists {
			return nil, stacktrace.NewError(
				"Invalid authorization header: duplicate parameter %v",
				key)
		}

		result[key] = value
	}

	return result, nil
}

// GetSignedHeaders returns a slice containing the signed header names and
// values.
//
// This is returned as a sorted list of values since the order of the headers
// is important in the signature calculation.
//
// Either the X-Amz-SignedHeaders query parameter or the SignedHeaders
// authorization header parameter must be present or an error is returned.
//
// If multiple X-Amz-SignedHeaders query parameters are present, or the
// X-Amz-SignedHeaders query parameter cannot be decoded, an error is returned.
//
// If the signed headers value is not canonicalized -- that is, all elements
// are lower-cased and sorted -- an error is returned. For example,
// "a;b;c;d" is valid, but "a;B;c;d", "a;c;b;d", and "A;C;B;D" are not.
//
// Finally, all headers must be present in the request or an error is returned.
func (r *Request) GetSignedHeaders() ([]SignedHeader, error) {
	var qpmap map[string][]string
	var qpSignedHeaders []string
	var signedHeaders string
	var ok bool
	var err error
	results := make([]SignedHeader, 0)

	if qpmap, err = NormalizeQueryParameters(r.QueryString); err != nil {
		return nil, stacktrace.Propagate(
			err, "Unable to get signed headers: %#v", r.QueryString)
	}

	if qpSignedHeaders, ok = qpmap[keyXAmzSignedHeaders]; ok && len(qpSignedHeaders) > 0 {
		if len(qpSignedHeaders) > 1 {
			return nil, stacktrace.NewError(
				"Unable to get signed headers: query parameter %s has multiple values",
				keyXAmzSignedHeaders)
		}

		if signedHeaders, err = url.QueryUnescape(qpSignedHeaders[0]); err != nil {
			return nil, stacktrace.Propagate(
				err, "Unable to get signed headers: unable to unescape query parameter %v: %#v",
				keyXAmzSignedHeaders, qpSignedHeaders[0])
		}
	} else {
		ahparam, err := r.GetAuthorizationHeaderParameters()
		if err != nil {
			return nil, stacktrace.Propagate(err, "Unable to get signed headers")
		}

		if signedHeaders, ok = ahparam[keySignedHeaders]; !ok {
			return nil, stacktrace.NewError(
				"Unable to get signed headers: query parameter %s missing and authorization parameter %s missing",
				keyXAmzSignedHeaders, keySignedHeaders)
		}
	}

	// Header names are separated by semicolons.
	parts := strings.Split(signedHeaders, ";")

	// Make sure the signed headers list is canonicalized. For security
	// reasons, we consider it an error if it isn't.
	for _, part := range parts {
		if lowerCased := strings.ToLower(part); lowerCased != part {
			return nil, stacktrace.NewError(
				"SignedHeaders is not canonicalized: %#v", signedHeaders)
		}
	}

	if !sort.StringsAreSorted(parts) {
		return nil, stacktrace.NewError(
			"SignedHeaders is not canonicalized: %#v", signedHeaders)
	}

	for _, header := range parts {
		values, found := r.Headers[header]
		if !found {
			return nil, stacktrace.NewError("SignedHeader missing: %v", header)
		}

		replacedValues := make([]string, len(values))
		for i, value := range values {
			replacedValues[i] = multispace.ReplaceAllString(value, " ")
		}

		results = append(
			results, SignedHeader{header, strings.Join(replacedValues, ",")})
	}

	return results, nil
}

// GetRequestTimestamp returns the timestamp of the request.
func (r *Request) GetRequestTimestamp() (time.Time, error) {
	var result time.Time
	var qpmap map[string][]string
	var dateStrings []string
	var dateString string
	var ok bool
	var err error

	if qpmap, err = NormalizeQueryParameters(r.QueryString); err != nil {
		return time.Time{}, stacktrace.Propagate(
			err, "Unable to get request timestamp: %#v", r.QueryString)
	}

	if dateStrings, ok = qpmap[keyXAmzDate]; ok && len(dateStrings) > 0 {
		if len(dateStrings) > 1 {
			return time.Time{}, stacktrace.NewError(
				"Unable to get request timestamp: query parameter %s has multiple values",
				keyXAmzDate)
		}

		if dateString, err = url.QueryUnescape(dateStrings[0]); err != nil {
			return time.Time{}, stacktrace.Propagate(
				err, "Unable to get request timestamp: unable to unescape query parameter %v: %#v",
				keyXAmzDate, dateStrings[0])
		}
	} else {
		if dateStrings, ok = r.Headers[keyXAmzDateLower]; ok && len(dateStrings) > 0 {
			if len(dateStrings) > 1 {
				return time.Time{}, stacktrace.NewError(
					"Unable to get request timestamp: multiple %s headers present", keyXAmzDateLower)
			}
		} else {
			if dateStrings, ok = r.Headers[keyDate]; !ok || len(dateStrings) == 0 {
				return time.Time{}, stacktrace.NewError(
					"Unable to get request timestamp: query parameter %s, header %s, and header %s were not passed into the request",
					keyXAmzDate, keyXAmzDateLower, keyDate)
			}

			if len(dateStrings) > 1 {
				return time.Time{}, stacktrace.NewError(
					"Unable to get request timestamp: multiple %s headers present", keyDate)
			}
		}

		dateString = dateStrings[0]
	}

	if result, err = timeutil.ParseISO8601Timestamp(dateString); err != nil {
		if result, err = time.Parse(time.RFC1123Z, dateString); err != nil {

		}
	}
	return result, nil
}

// GetCredentialScope returns the scope of the credentials to use, as
// calculated by the service's region and name, but using the timestamp of
// the request.
func (r *Request) GetCredentialScope() (string, error) {
	ts, err := r.GetRequestTimestamp()

	if err != nil {
		return "", stacktrace.Propagate(err, "Unable to get credential scope")
	}

	date := ts.Format("20060102")
	return date + "/" + r.Region + "/" + r.Service + "/" + keyAWS4Request, nil
}

// GetAccessKey returns the access key used to sign the request.
//
// If the credential scope does not match our expected credential scope,
// an error is returned.
func (r *Request) GetAccessKey() (string, error) {
	qp, err := NormalizeQueryParameters(r.QueryString)
	if err != nil {
		return "", stacktrace.Propagate(err, "Unable to get access key")
	}

	var cred string
	creds, qpExists := qp[keyXAmzCredential]
	if qpExists {
		if len(creds) > 1 {
			return "", stacktrace.NewError(
				"Unable to get access key: multiple X-Amz-Credential query " +
					"parameters present")
		}

		cred = creds[0]
	} else {
		authHeaders, err := r.GetAuthorizationHeaderParameters()
		if err != nil {
			return "", stacktrace.Propagate(
				err, "Unable to get access key: missing both "+
					"X-Amz-Credential query parameter and AWS4-HMAC-SHA256 "+
					"authorization header")
		}

		var credExists bool
		cred, credExists = authHeaders[keyCredential]
		if !credExists {
			return "", stacktrace.NewError(
				"Unable to get access key: AWS4-HMAC-SHA256 authorization " +
					"header is missing the Credential parameter")
		}
	}

	parts := strings.SplitN(cred, "/", 2)
	if len(parts) != 2 {
		return "", stacktrace.NewError(
			"Unable to get access key: Malformed credential")
	}

	accessKey := parts[0]
	requestScope := parts[1]
	serverScope, err := r.GetCredentialScope()
	if err != nil {
		return "", stacktrace.Propagate(
			err, "Unable to get access key: unable to get expected "+
				"credential scope")
	}

	if requestScope != serverScope {
		return "", stacktrace.NewError(
			"Invalid credential scope: Expected %#v instead of %#v",
			serverScope, requestScope)
	}

	return accessKey, nil
}

// GetSessionToken returns the session token sent with the access key.
//
// Session tokens are used only for temporary credentials. If a long-term
// credential was used, the result is "", nil.
func (r *Request) GetSessionToken() (string, error) {
	qp, err := NormalizeQueryParameters(r.QueryString)
	if err != nil {
		return "", stacktrace.Propagate(err, "Unable to get session token key")
	}

	sessionTokens, qpExists := qp[keyXAmzSecurityToken]
	if qpExists {
		if len(sessionTokens) > 1 {
			return "", stacktrace.NewError(
				"Unable to get session token: multiple X-Security-Token " +
					"query parameters present")
		}

		return sessionTokens[0], nil
	}

	authHeaders, err := r.GetAuthorizationHeaderParameters()
	if err != nil {
		return "", stacktrace.Propagate(
			err, "Unable to get session token key: missing both "+
				"X-Security-Token query parameter and AWS4-HMAC-SHA256 "+
				"authorization header")
	}

	// Returning an empty value is ok here.
	return authHeaders[keyXAmzSecurityTokenLower], nil
}

// GetRequestSignature returns the signature passed into the request,
// either from the query parameter X-Amz-Signature or the Signature
// parameter in the AWS4-HMAC-SHA256 authorization header.
func (r *Request) GetRequestSignature() (string, error) {
	qp, err := NormalizeQueryParameters(r.QueryString)
	if err != nil {
		return "", stacktrace.Propagate(err, "Unable to get request signature")
	}

	signatures, qpExists := qp[keyXAmzSignature]
	if qpExists {
		if len(signatures) > 1 {
			return "", stacktrace.NewError(
				"Unable to get signature: multiple X-Amz-Signature query " +
					"parameters present")
		}

		return signatures[0], nil
	}

	authHeaders, err := r.GetAuthorizationHeaderParameters()
	if err != nil {
		return "", stacktrace.Propagate(
			err, "Unable to get signature: missing both X-Amz-Signature "+
				"query parameter and AWS4-HMAC-SHA256 authorization header")
	}

	signature, sigExists := authHeaders[keySignature]
	if !sigExists {
		return "", stacktrace.NewError(
			"Invalid Authorization header: missing Signature parameter")
	}

	return signature, nil
}

// GetCanonicalRequest returns the AWS SigV4 canonical request from the
// request parameters. The process is outlined here:
// http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
//
// The canonical request is:
//     request_method + '\n' +
//     canonical_uri_path + '\n' +
//     canonical_query_string + '\n' +
//     signed_headers + '\n' +
//     sha256(body).hexdigest()
func (r *Request) GetCanonicalRequest() ([]byte, error) {
	canonicalURIPath, err := r.GetCanonicalizedURIPath()
	if err != nil {
		return nil, stacktrace.Propagate(
			err, "Unable to get canonical request: Failed to get "+
				"canonicalized URI path")
	}

	canonicalQueryString, err := r.GetCanonicalQueryString()
	if err != nil {
		return nil, stacktrace.Propagate(
			err, "Unable to get canonical request: Failed to get canonical "+
				"query string")
	}

	signedHeaders, err := r.GetSignedHeaders()
	if err != nil {
		return nil, stacktrace.Propagate(
			err, "Unable to get canonical request: Failed to get signed "+
				"headers")
	}

	contentType, _, err := r.GetContentTypeAndCharset()
	if err != nil {
		return nil, stacktrace.Propagate(
			err, "Unable to get canonical request: Failed to get "+
				"content-type header")
	}

	creq := new(bytes.Buffer)
	_, err = creq.WriteString(r.RequestMethod)
	if err != nil {
		return nil, stacktrace.Propagate(err, msgFailedToGetCReqBuf)
	}

	err = creq.WriteByte('\n')
	if err != nil {
		return nil, stacktrace.Propagate(err, msgFailedToGetCReqBuf)
	}

	_, err = creq.WriteString(canonicalURIPath)
	if err != nil {
		return nil, stacktrace.Propagate(err, msgFailedToGetCReqBuf)
	}

	err = creq.WriteByte('\n')
	if err != nil {
		return nil, stacktrace.Propagate(err, msgFailedToGetCReqBuf)
	}

	_, err = creq.WriteString(canonicalQueryString)
	if err != nil {
		return nil, stacktrace.Propagate(err, msgFailedToGetCReqBuf)
	}

	for _, signedHeader := range signedHeaders {
		err = creq.WriteByte('\n')
		if err != nil {
			return nil, stacktrace.Propagate(err, msgFailedToGetCReqBuf)
		}

		_, err = creq.WriteString(signedHeader.Name)
		if err != nil {
			return nil, stacktrace.Propagate(err, msgFailedToGetCReqBuf)
		}

		err = creq.WriteByte(':')
		if err != nil {
			return nil, stacktrace.Propagate(err, msgFailedToGetCReqBuf)
		}

		_, err = creq.WriteString(signedHeader.Value)
		if err != nil {
			return nil, stacktrace.Propagate(err, msgFailedToGetCReqBuf)
		}
	}

	err = creq.WriteByte('\n')
	if err != nil {
		return nil, stacktrace.Propagate(err, msgFailedToGetCReqBuf)
	}

	firstHeader := true
	for _, signedHeader := range signedHeaders {
		if firstHeader {
			firstHeader = false
		} else {
			err = creq.WriteByte(';')
			if err != nil {
				return nil, stacktrace.Propagate(err, msgFailedToGetCReqBuf)
			}
		}

		_, err = creq.WriteString(signedHeader.Name)
		if err != nil {
			return nil, stacktrace.Propagate(err, msgFailedToGetCReqBuf)
		}
	}

	err = creq.WriteByte('\n')
	if err != nil {
		return nil, stacktrace.Propagate(err, msgFailedToGetCReqBuf)
	}

	var bodyHexDigest string
	if contentType == keyApplicationXWWWFormURLEncoded {
		// Body is used as query string; return the SHA-256 digest of the
		// empty string
		bodyHexDigest = sha256Empty
	} else {
		bodyHexDigest = r.GetBodyDigest()
	}

	_, err = creq.WriteString(bodyHexDigest)
	if err != nil {
		return nil, stacktrace.Propagate(err, msgFailedToGetCReqBuf)
	}

	return creq.Bytes(), nil
}

// GetBodyDigest returns the SHA-256 hex digest of the request body.
func (r *Request) GetBodyDigest() string {
	digest := sha256.Sum256([]byte(r.Body))
	return hex.EncodeToString(digest[:])
}

// GetStringToSign returns the expected string that should be signed for
// the request.
func (r *Request) GetStringToSign() (string, error) {
	ts, err := r.GetRequestTimestamp()
	if err != nil {
		return "", stacktrace.Propagate(
			err, "Unable to get string to sign: Failed to get request "+
				"timestamp")
	}

	credScope, err := r.GetCredentialScope()
	if err != nil {
		return "", stacktrace.Propagate(
			err, "Unable to get string to sign: Failed to get credential "+
				"scope")
	}

	cReq, err := r.GetCanonicalRequest()
	if err != nil {
		return "", stacktrace.Propagate(
			err, "Unable to get string to sign: Failed to get canonical "+
				"request")
	}

	creqSha256 := sha256.Sum256(cReq)
	return (keyAWS4HMACSHA256 + "\n" +
		ts.Format(iso8601CompactFormat) + "\n" +
		credScope + "\n" +
		hex.EncodeToString(creqSha256[:])), nil
}

// GetExpectedSignature returns the expected signature for the request given
// the request and a function that returns the secret key given an access
// key and optional session token.
func (r *Request) GetExpectedSignature(secretKeyFn func(string, string) (string, error)) (string, error) {
	accessKey, err := r.GetAccessKey()
	if err != nil {
		return "", stacktrace.Propagate(
			err, "Unable to get expected signature: Failed to get access key")
	}

	sessionToken, err := r.GetSessionToken()
	if err != nil {
		return "", stacktrace.Propagate(
			err, "Unable to get expected signature: Failed to get session "+
				"token")
	}

	secretKey, err := secretKeyFn(accessKey, sessionToken)
	if err != nil {
		return "", stacktrace.Propagate(
			err, "Unable to get expected signature: Failed to get secret "+
				"key")
	}

	ts, err := r.GetRequestTimestamp()
	if err != nil {
		return "", stacktrace.Propagate(
			err, "Unable to get expected signature: Failed to get request "+
				"timestamp")
	}
	reqDate := ts.Format("20060102")
	sts, err := r.GetStringToSign()
	if err != nil {
		return "", stacktrace.Propagate(
			err, "Unable to get expected signature: Failed to get string to "+
				"sign")
	}

	kDate := hmac.New(sha256.New, []byte(keyAWS4+secretKey)).Sum([]byte(reqDate))
	kRegion := hmac.New(sha256.New, kDate).Sum([]byte(r.Region))
	kService := hmac.New(sha256.New, kRegion).Sum([]byte(r.Service))
	kSigning := hmac.New(sha256.New, kService).Sum([]byte(keyAWS4Request))
	signature := hmac.New(sha256.New, kSigning).Sum([]byte(sts))

	return hex.EncodeToString(signature), nil
}

// VerifyAt verifies that the request timestamp is not beyond the allowed
// timestamp mismatch and that the request signature matches our expected
// signature.
//
// This version allows you to specify the server timestamp for testing.
// For normal use, use Verify.
//
// To allow any amount of timestamp mismatch, pass time.Duration(-1) for the
// duration.
func (r *Request) VerifyAt(
	secretKeyFn func(string, string) (string, error),
	serverTimestamp time.Time,
	allowedMismatch time.Duration) error {
	if allowedMismatch >= time.Duration(0) {
		reqTS, err := r.GetRequestTimestamp()
		if err != nil {
			return stacktrace.Propagate(
				err, "Unable to verify signature: Failed to get request "+
					"timestamp")
		}

		minTS := serverTimestamp.Add(-allowedMismatch)
		maxTS := serverTimestamp.Add(allowedMismatch)

		if reqTS.Before(minTS) || reqTS.After(maxTS) {
			return stacktrace.NewError(
				"Signature verification failed: Request timestamp %v outside "+
					"of allowed range %v - %v",
				reqTS.Format(timeutil.ISO8601CompactFormat),
				minTS.Format(timeutil.ISO8601CompactFormat),
				maxTS.Format(timeutil.ISO8601CompactFormat))
		}
	}

	expectedSig, err := r.GetExpectedSignature(secretKeyFn)
	if err != nil {
		return stacktrace.Propagate(
			err, "Signature verification failed: Failed to calculate "+
				"expected signature")
	}

	requestSig, err := r.GetRequestSignature()
	if err != nil {
		return stacktrace.Propagate(
			err, "Signature verification failed: Failed to get request "+
				"signature")
	}

	if expectedSig != requestSig {
		return stacktrace.NewError(
			"Signature verification failed: Signature mismatch: Expected %#v "+
				"instead of %#v", expectedSig, requestSig)
	}

	return nil
}

// Verify verifies that the request timestamp is not beyond the allowed
// timestamp mismatch and that the request signature matches our expected
// signature.
//
// To allow any amount of timestamp mismatch, pass time.Duration(-1) for the
// duration.
func (r *Request) Verify(
	secretKeyFn func(string, string) (string, error),
	allowedMismatch time.Duration) error {
	return r.VerifyAt(secretKeyFn, time.Now(), allowedMismatch)
}

// IsRFC3986Unreserved indicates whether the s2pecified byte falls in the
// RFC 3986 range of unreserved characters. This is the following characters:
// %2D ('-'), %2E ('.'), %30-%39 ('0'-'9'), %41-%5A ('A'-'Z'), %5F ('_'),
// %61-%7A ('a'-'z'), %7E ('~').
func IsRFC3986Unreserved(c byte) bool {
	return ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		c == '-' ||
		c == '.' ||
		c == '_' ||
		c == '~')
}

// NormalizeURIPathComponent normalizes a path component according to RFC 3986.
// This performs the following operations:
//
// * Alpha, digit, and the symbols '-', '.', '_', and '~' (unreserved
// characters) are left alone.
//
// * Characters outside this range are percent-encoded.
//
// * Percent-encoded values are upper-cased ('%2a' becomes '%2A').
//
// * Plus signs ('+') are interpreted as encoded spaces and converted to '%20'.
//
// * Percent-encoded values in the RFC 3986 unreserved space are converted to
// normal characters.
//
// If a percent-encoding is invalid, an error is returned.
func NormalizeURIPathComponent(pathComponent string) (string, error) {
	result := strings.Builder{}

	for i := 0; i < len(pathComponent); {
		c := pathComponent[i]

		switch {
		case IsRFC3986Unreserved(c):
			result.WriteByte(c)
			i++

		case c == '%':
			if i+2 > len(pathComponent) {
				// % encoding would go beyond end of string
				return "", stacktrace.NewError(
					"Failed to normalize URI path component: '%%' encoding "+
						"truncated at index %d: %#v", i, pathComponent)
			}

			hexDigits := pathComponent[i+1 : i+3]
			var hexValue byte
			if nfmt, err := fmt.Sscanf(hexDigits, "%02X", &hexValue); err != nil {
				return "", stacktrace.Propagate(
					err, "Failed to normalize URI path component: "+
						"invalid hex-encoding sequence at index %d: %#v",
					i, pathComponent)
			} else if nfmt != 1 {
				return "", stacktrace.NewError(
					"Failed to normalize URI path component: "+
						"invalid hex-encoding sequence at index %d: %#v",
					i, pathComponent)
			}

			if IsRFC3986Unreserved(hexValue) {
				// Should not have been hex-encoded; just append the plain
				// character
				result.WriteByte(hexValue)
			} else {
				// Rewrite the hex-escape so it's always upper-cased.
				result.WriteString(fmt.Sprintf("%02X", hexValue))
			}

			i += 3

		case c == '+':
			// Plus-encoded space. Convert this to %20.
			result.WriteString("%20")
			i++

		default:
			// Character should have been encoded
			result.WriteString(fmt.Sprintf("%%%02X", c))
			i++
		}
	}

	return result.String(), nil
}

// CanonicalizeURIPath normalizes a specified URI path, removing redundant
// slashes and relative path components.
//
// The uriPath must be absolute (start with "/") or empty (assumed to be "/").
//
// If a current-directory relative path component (".") is encountered, it is
// removed. For example, "/a/b/./c" becomes "/a/b/c".
//
// If a parent-directory relative path component ("..") is encountered, it
// and the preceding component are removed. For example, "/a/b/../c" becomes
// "/a/c". Attempts to to above the root (e.g. "/a/../../b") result in an
// error.
//
// If any component fails to normalize according to the rules of
// NormalizeURIPathComponent, an error is returned.
func CanonicalizeURIPath(uriPath string) (string, error) {
	// Special case: empty path is converted to '/'; also short-circuit the
	// usual '/' path here.
	if uriPath == "" || uriPath == "/" {
		return "/", nil
	}

	// All other paths must be absolute
	if !strings.HasPrefix(uriPath, "/") {
		return "", stacktrace.NewError("Path is not absolute: %#v", uriPath)
	}

	// Replace double slashes; this makes it easier to handle slashes at the
	// end.
	uriPath = multislash.ReplaceAllString(uriPath, "/")

	// Examine each path component for relative directories
	components := strings.Split(uriPath, "/")

	// Ignore the leading "/"
	for i := 1; i < len(components); {
		component, err := NormalizeURIPathComponent(components[i])
		if err != nil {
			return "", stacktrace.Propagate(
				err, "Invalid path component: %#v", components[i])
		}

		switch component {
		case ".":
			// Relative path: current directory; remove this. i now points to
			// the next element, so don't increment it.
			components = append(components[:i], components[i+1:]...)

		case "..":
			// Relative path: parent directory. Remove this and the previouse
			// component.
			if i <= 1 {
				// Not allowed at the beginning
				return "", stacktrace.NewError(
					"Invalid URI path: relative path entry '..' navigates "+
						"above root: %#v", uriPath)
			}

			components = append(components[:i-1], components[i+1:]...)

			// Since we've deleted two components, we need to back up one to
			// examine what's now the next component.
			i--

		default:
			// Leave it alone; proceed to the next component.
			i++
		}
	}

	switch len(components) {
	case 0:
		panic(fmt.Sprintf("Empty components after processing URI: %#v", uriPath))

	case 1:
		return "/", nil

	default:
		return strings.Join(components, "/"), nil
	}
}

// NormalizeQueryParameters converts a query string into a map of parameter
// names to a list of sorted values.  This ensurses that the query string
// follows RFC 3986 percent-encoding rules and checks for duplicate keys.
//
// If a percent encoding is invalid, an error is returned.
func NormalizeQueryParameters(queryString string) (map[string][]string, error) {
	result := make(map[string][]string)

	if queryString == "" {
		return result, nil
	}

	components := strings.Split(queryString, "&")
	for _, component := range components {
		if component == "" {
			// Empty component; skip it.
			continue
		}

		componentParts := strings.SplitN(component, "=", 2)
		var key, value string

		if len(componentParts) == 2 {
			key = componentParts[0]
			value = componentParts[1]
		} else {
			key = componentParts[0]
			value = ""
		}

		var err error
		if key, err = NormalizeURIPathComponent(key); err != nil {
			return nil, stacktrace.Propagate(
				err, "Invalid query string: failed to normalize query "+
					"component: %#v", component)
		}

		if value, err = NormalizeURIPathComponent(value); err != nil {
			return nil, stacktrace.Propagate(
				err, "Invalid query string: failed to normalize query "+
					"component: %#v", component)
		}

		current, exists := result[key]
		if !exists {
			current = make([]string, 1)
			current[0] = value
		} else {
			current = append(current, value)
		}
		result[key] = current
	}

	for key := range result {
		sort.Strings(result[key])
	}

	return result, nil
}
