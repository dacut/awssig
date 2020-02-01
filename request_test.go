package awssig

import (
	"bufio"
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/palantir/stacktrace"
)

type WriteToTesting struct {
	t *testing.T
}

func (wtt *WriteToTesting) Write(p []byte) (n int, err error) {
	wtt.t.Logf("%s", p)
	return len(p), nil
}

func TestNormalizeURIPathComponent(t *testing.T) {
	result, err := NormalizeURIPathComponent("ሴ")
	if err != nil {
		t.Errorf("NormalizeURIPathComponent should not have failed for ሴ\n")
	}

	if result != "%E1%88%B4" {
		t.Errorf("ሴ should have translated to %%E1%%88%%B4: %#v\n", result)
	}
}

func TestGetHeaderKeyDuplicateGetHeaderKeyDuplicate(t *testing.T) {
	wtt := WriteToTesting{t}
	log.SetOutput(&wtt)
	err := runAWSTestCase("get-header-key-duplicate/get-header-key-duplicate", t)
	if err != nil {
		t.Errorf("Test case get-header-key-duplicate/get-header-key-duplicate failed: %#v", err)
	}
}

func TestGetHeaderValueMultilineGetHeaderValueMultiline(t *testing.T) {
	err := runAWSTestCase("get-header-value-multiline/get-header-value-multiline", t)
	if err != nil {
		t.Errorf("Test case get-header-value-multiline/get-header-value-multiline failed: %#v", err)
	}
}

func TestGetHeaderValueOrderGetHeaderValueOrder(t *testing.T) {
	err := runAWSTestCase("get-header-value-order/get-header-value-order", t)
	if err != nil {
		t.Errorf("Test case get-header-value-order/get-header-value-order failed: %#v", err)
	}
}

func TestGetHeaderValueTrimGetHeaderValueTrim(t *testing.T) {
	err := runAWSTestCase("get-header-value-trim/get-header-value-trim", t)
	if err != nil {
		t.Errorf("Test case get-header-value-trim/get-header-value-trim failed: %#v", err)
	}
}

func TestGetUnreservedGetUnreserved(t *testing.T) {
	err := runAWSTestCase("get-unreserved/get-unreserved", t)
	if err != nil {
		t.Errorf("Test case get-unreserved/get-unreserved failed: %#v", err)
	}
}

func TestGetUTF8GetUTF8(t *testing.T) {
	wtt := WriteToTesting{t}
	log.SetOutput(&wtt)
	err := runAWSTestCase("get-utf8/get-utf8", t)
	if err != nil {
		t.Errorf("Test case get-utf8/get-utf8 failed: %#v", err)
	}
}

func TestGetVanillaEmptyQueryKeyGetVanillaEmptyQueryKey(t *testing.T) {
	err := runAWSTestCase("get-vanilla-empty-query-key/get-vanilla-empty-query-key", t)
	if err != nil {
		t.Errorf("Test case get-vanilla-empty-query-key/get-vanilla-empty-query-key failed: %#v", err)
	}
}

func TestGetVanillaQueryOrderKeyCaseGetVanillaQueryOrderKeyCase(t *testing.T) {
	err := runAWSTestCase("get-vanilla-query-order-key-case/get-vanilla-query-order-key-case", t)
	if err != nil {
		t.Errorf("Test case get-vanilla-query-order-key-case/get-vanilla-query-order-key-case failed: %#v", err)
	}
}

func TestGetVanillaQueryOrderKeyGetVanillaQueryOrderKey(t *testing.T) {
	err := runAWSTestCase("get-vanilla-query-order-key/get-vanilla-query-order-key", t)
	if err != nil {
		t.Errorf("Test case get-vanilla-query-order-key/get-vanilla-query-order-key failed: %#v", err)
	}
}

func TestGetVanillaQueryOrderValueGetVanillaQueryOrderValue(t *testing.T) {
	err := runAWSTestCase("get-vanilla-query-order-value/get-vanilla-query-order-value", t)
	if err != nil {
		t.Errorf("Test case get-vanilla-query-order-value/get-vanilla-query-order-value failed: %#v", err)
	}
}

func TestGetVanillaQueryUnreservedGetVanillaQueryUnreserved(t *testing.T) {
	err := runAWSTestCase("get-vanilla-query-unreserved/get-vanilla-query-unreserved", t)
	if err != nil {
		t.Errorf("Test case get-vanilla-query-unreserved/get-vanilla-query-unreserved failed: %#v", err)
	}
}

func TestGetVanillaQueryGetVanillaQuery(t *testing.T) {
	err := runAWSTestCase("get-vanilla-query/get-vanilla-query", t)
	if err != nil {
		t.Errorf("Test case get-vanilla-query/get-vanilla-query failed: %#v", err)
	}
}

func TestGetVanillaUTF8QueryGetVanillaUTF8Query(t *testing.T) {
	err := runAWSTestCase("get-vanilla-utf8-query/get-vanilla-utf8-query", t)
	if err != nil {
		t.Errorf("Test case get-vanilla-utf8-query/get-vanilla-utf8-query failed: %#v", err)
	}
}

func TestGetVanillaGetVanilla(t *testing.T) {
	err := runAWSTestCase("get-vanilla/get-vanilla", t)
	if err != nil {
		t.Errorf("Test case get-vanilla/get-vanilla failed: %#v", err)
	}
}

func TestNormalizePathGetRelativeRelativeGetRelativeRelative(t *testing.T) {
	err := runAWSTestCase("normalize-path/get-relative-relative/get-relative-relative", t)
	if err != nil {
		t.Errorf("Test case normalize-path/get-relative-relative/get-relative-relative failed: %#v", err)
	}
}

func TestNormalizePathGetRelativeGetRelative(t *testing.T) {
	err := runAWSTestCase("normalize-path/get-relative/get-relative", t)
	if err != nil {
		t.Errorf("Test case normalize-path/get-relative/get-relative failed: %#v", err)
	}
}

func TestNormalizePathGetSlashDotSlashGetSlashDotSlash(t *testing.T) {
	err := runAWSTestCase("normalize-path/get-slash-dot-slash/get-slash-dot-slash", t)
	if err != nil {
		t.Errorf("Test case normalize-path/get-slash-dot-slash/get-slash-dot-slash failed: %#v", err)
	}
}

func TestNormalizePathGetSlashPointlessDotGetSlashPointlessDot(t *testing.T) {
	err := runAWSTestCase("normalize-path/get-slash-pointless-dot/get-slash-pointless-dot", t)
	if err != nil {
		t.Errorf("Test case normalize-path/get-slash-pointless-dot/get-slash-pointless-dot failed: %#v", err)
	}
}

func TestNormalizePathGetSlashGetSlash(t *testing.T) {
	err := runAWSTestCase("normalize-path/get-slash/get-slash", t)
	if err != nil {
		t.Errorf("Test case normalize-path/get-slash/get-slash failed: %#v", err)
	}
}

func TestNormalizePathGetSlashesGetSlashes(t *testing.T) {
	err := runAWSTestCase("normalize-path/get-slashes/get-slashes", t)
	if err != nil {
		t.Errorf("Test case normalize-path/get-slashes/get-slashes failed: %#v", err)
	}
}

func TestNormalizePathGetSpaceGetSpace(t *testing.T) {
	err := runAWSTestCase("normalize-path/get-space/get-space", t)
	if err != nil {
		t.Errorf("Test case normalize-path/get-space/get-space failed: %#v", err)
	}
}

func TestPostHeaderKeyCasePostHeaderKeyCase(t *testing.T) {
	err := runAWSTestCase("post-header-key-case/post-header-key-case", t)
	if err != nil {
		t.Errorf("Test case post-header-key-case/post-header-key-case failed: %#v", err)
	}
}

func TestPostHeaderKeySortPostHeaderKeySort(t *testing.T) {
	err := runAWSTestCase("post-header-key-sort/post-header-key-sort", t)
	if err != nil {
		t.Errorf("Test case post-header-key-sort/post-header-key-sort failed: %#v", err)
	}
}

func TestPostHeaderValueCasePostHeaderValueCase(t *testing.T) {
	err := runAWSTestCase("post-header-value-case/post-header-value-case", t)
	if err != nil {
		t.Errorf("Test case post-header-value-case/post-header-value-case failed: %#v", err)
	}
}

func TestPostStsTokenPostStsHeaderAfterPostStsHeaderAfter(t *testing.T) {
	err := runAWSTestCase("post-sts-token/post-sts-header-after/post-sts-header-after", t)
	if err != nil {
		t.Errorf("Test case post-sts-token/post-sts-header-after/post-sts-header-after failed: %#v", err)
	}
}

func TestPostStsTokenPostStsHeaderBeforePostStsHeaderBefore(t *testing.T) {
	err := runAWSTestCase("post-sts-token/post-sts-header-before/post-sts-header-before", t)
	if err != nil {
		t.Errorf("Test case post-sts-token/post-sts-header-before/post-sts-header-before failed: %#v", err)
	}
}

func TestPostVanillaEmptyQueryValuePostVanillaEmptyQueryValue(t *testing.T) {
	err := runAWSTestCase("post-vanilla-empty-query-value/post-vanilla-empty-query-value", t)
	if err != nil {
		t.Errorf("Test case post-vanilla-empty-query-value/post-vanilla-empty-query-value failed: %#v", err)
	}
}

func TestPostVanillaQueryPostVanillaQuery(t *testing.T) {
	wtt := WriteToTesting{t}
	log.SetOutput(&wtt)
	log.Printf("Testing the log\n")
	err := runAWSTestCase("post-vanilla-query/post-vanilla-query", t)
	if err != nil {
		t.Errorf("Test case post-vanilla-query/post-vanilla-query failed: %#v", err)
	}
}

func TestPostVanillaPostVanilla(t *testing.T) {
	wtt := WriteToTesting{t}
	log.SetOutput(&wtt)
	log.Printf("Testing the log\n")
	err := runAWSTestCase("post-vanilla/post-vanilla", t)
	if err != nil {
		t.Errorf("Test case post-vanilla/post-vanilla failed: %#v", err)
	}
}

func TestPostXWWWFormUrlencodedParametersPostXWWWFormUrlencodedParameters(t *testing.T) {
	err := runAWSTestCase("post-x-www-form-urlencoded-parameters/post-x-www-form-urlencoded-parameters", t)
	if err != nil {
		t.Errorf("Test case post-x-www-form-urlencoded-parameters/post-x-www-form-urlencoded-parameters failed: %#v", err)
	}
}

func TestPostXWWWFormUrlencodedPostXWWWFormUrlencoded(t *testing.T) {
	t.Skip("Skipping test: test case is malformed")
	err := runAWSTestCase("post-x-www-form-urlencoded/post-x-www-form-urlencoded", t)
	if err != nil {
		t.Errorf("Test case post-x-www-form-urlencoded/post-x-www-form-urlencoded failed: %#v", err)
	}
}

var methodLineRegex *regexp.Regexp

func init() {
	methodLineRegex = regexp.MustCompile(`^([A-Z]+) +([^?]*)(?:\?(.*))? (HTTP/[^ ]+)$`)
}

func runAWSTestCase(basename string, t *testing.T) error {
	reqPath := "aws-sig-v4-test-suite/" + basename
	sreqPath := reqPath + ".sreq"
	creqPath := reqPath + ".creq"
	stsPath := reqPath + ".sts"

	t.Logf("Opening %v", sreqPath)
	sreqFile, err := os.Open(sreqPath)
	if err != nil {
		return stacktrace.Propagate(
			err, "Unable to open signed request file %#v", sreqPath)
	}

	sreqReader := bufio.NewReader(sreqFile)
	methodLine, err := sreqReader.ReadString('\n')
	if err != nil {
		return stacktrace.Propagate(
			err, "Failed to read method line from %#v", sreqFile)
	}

	muqParts := methodLineRegex.FindStringSubmatchIndex(methodLine)
	if muqParts[2] < 0 || muqParts[4] < 0 || muqParts[8] < 0 {
		return stacktrace.NewError(
			"Invalid method line from %#v: %v", sreqFile, methodLine)
	}

	requestMethod := methodLine[muqParts[2]:muqParts[3]]
	uriPath := methodLine[muqParts[4]:muqParts[5]]
	var queryString string

	if muqParts[6] > 0 {
		queryString = methodLine[muqParts[6]:muqParts[7]]
	}

	var lastKey string
	var headers map[string][]string = make(map[string][]string)

	t.Log("Reading headers")
	lineNo := 1

	for {
		lineNo++
		line, err := sreqReader.ReadString('\n')
		if err != nil && err != io.EOF {
			return stacktrace.Propagate(err, "Failed to read all headers from %s", sreqPath)
		}

		line = strings.TrimSuffix(line, "\n")

		if len(line) == 0 {
			break
		}

		var key string
		var value string

		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if lastKey == "" {
				return stacktrace.NewError(
					"Continuation header at start of headers in %s", sreqPath)
			}

			key = lastKey
			value = strings.TrimLeft(line, " \t")
			t.Logf("Continuation value: untrimmed=%#v, trimmed=%#v", line, value)
		} else {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				return stacktrace.NewError(
					"Malformed header line in %s %d: %v", sreqPath, lineNo, line)
			}

			key = strings.ToLower(parts[0])
			value = strings.TrimSpace(parts[1])
		}

		lastKey = key
		keyValues, found := headers[key]
		if !found {
			keyValues = make([]string, 0)
		}

		keyValues = append(keyValues, value)
		headers[key] = keyValues
	}

	t.Log("Done reading headers")

	body := make([]byte, 0)
	bodyBuffer := make([]byte, 65536)
	for {
		nRead, err := sreqReader.Read(bodyBuffer)
		if nRead == 0 && err == io.EOF {
			break
		}

		if err != nil {
			return stacktrace.Propagate(
				err, "Failed while reading body from %s", sreqPath)
		}

		body = append(body, bodyBuffer[:nRead]...)
	}

	r := Request{
		RequestMethod: requestMethod,
		URIPath:       uriPath,
		QueryString:   queryString,
		Headers:       headers,
		Body:          string(body),
		Region:        "us-east-1",
		Service:       "service",
	}

	t.Logf("Created request: %v", r)

	expectedCReq, err := ioutil.ReadFile(creqPath)
	if err != nil {
		return stacktrace.Propagate(
			err, "Failed to read canonical request file %#v", creqPath)
	}

	calculatedCReq, err := r.GetCanonicalRequest()
	if err != nil {
		return stacktrace.Propagate(
			err, "Failed to calculate canonical request on %#v", sreqPath)
	}

	t.Logf("Calculated CReq:\n%v\n--------", string(calculatedCReq))
	t.Logf("Expected CReq:\n%v\n--------", string(expectedCReq))

	if !bytes.Equal(expectedCReq, calculatedCReq) {
		return stacktrace.NewError(
			"Canoncial request differs for %#v: expected %#v, calculated %#v",
			sreqPath, expectedCReq, calculatedCReq)
	}

	expectedSTS, err := ioutil.ReadFile(stsPath)
	if err != nil {
		return stacktrace.Propagate(
			err, "Failed to read string to sign file %#v", stsPath)
	}

	calculatedSTS, err := r.GetStringToSign()
	if err != nil {
		return stacktrace.Propagate(
			err, "Failed to calculate string to sign on %#v", sreqPath)
	}

	t.Logf("Calculated STS: %#v\n", calculatedSTS)
	t.Logf("Expected STS:   %#v\n", string(expectedSTS))

	if string(expectedSTS) != calculatedSTS {
		return stacktrace.NewError(
			"String to sign differs for %#v: expected %#v, calculated %#v",
			sreqPath, expectedSTS, calculatedSTS)
	}

	secretKeyFn := func(_, _ string) (string, error) {
		return "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", nil
	}

	return r.Verify(secretKeyFn, -1)
}
