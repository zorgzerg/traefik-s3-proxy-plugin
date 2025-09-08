package s3

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

func generatePresignedURL(accessKeyID, secretAccessKey, region, endpoint, bucket, linkStyle, key string) (string, error) {
	escapedKey := url.PathEscape(key)

	var host, canonicalURI string

	switch linkStyle {
	case "path":
		// path-style: https://endpoint/bucket/key
		host = endpoint
		canonicalURI = fmt.Sprintf("/%s/%s", bucket, escapedKey)
	case "vhost":
		// virtual-hosted-style: https://bucket.endpoint/key
		host = fmt.Sprintf("%s.%s", bucket, endpoint)
		canonicalURI = fmt.Sprintf("/%s", escapedKey)
	default:
		return "", errors.New("invalid LinkStyle param")
	}

	t := time.Now().UTC()
	date := t.Format("20060102")
	timestamp := t.Format("20060102T150405Z")

	// Step 1: Build query parameters (without signature)
	query := url.Values{}
	query.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	query.Set("X-Amz-Credential", fmt.Sprintf("%s/%s/%s/s3/aws4_request", accessKeyID, date, region))
	query.Set("X-Amz-Date", timestamp)
	query.Set("X-Amz-Expires", "86400")
	query.Set("X-Amz-SignedHeaders", "host")

	// Step 2: Canonical query string (sorted)
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var canonicalQueryParts []string
	for _, k := range keys {
		for _, v := range query[k] {
			canonicalQueryParts = append(canonicalQueryParts, fmt.Sprintf("%s=%s", url.QueryEscape(k), url.QueryEscape(v)))
		}
	}
	canonicalQueryString := strings.Join(canonicalQueryParts, "&")

	// Step 3: Canonical request
	canonicalHeaders := fmt.Sprintf("host:%s\n", host)
	signedHeaders := "host"
	payloadHash := "UNSIGNED-PAYLOAD"

	canonicalRequest := strings.Join([]string{
		"GET",
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	// Step 4: String to sign
	credentialScope := fmt.Sprintf("%s/%s/s3/aws4_request", date, region)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		timestamp,
		credentialScope,
		hex.EncodeToString(hashSHA256(canonicalRequest)),
	}, "\n")

	// Step 5: Signature
	signingKey := getSigningKey(secretAccessKey, date, region)
	signature := hmacSHA256Hex(signingKey, stringToSign)

	// Step 6: Final URL
	query.Set("X-Amz-Signature", signature)
	finalURL := fmt.Sprintf("https://%s%s?%s", host, canonicalURI, query.Encode())

	return finalURL, nil
}

// Helper function to create the HMAC-SHA256 hash
func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// Helper function to create the hex-encoded HMAC-SHA256 hash
func hmacSHA256Hex(key []byte, data string) string {
	return hex.EncodeToString(hmacSHA256(key, data))
}

// Hash function for the payload
func hashSHA256(payload string) []byte {
	h := sha256.New()
	h.Write([]byte(payload))
	return h.Sum(nil)
}

func getSigningKey(secret, date, region string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, "s3")
	kSigning := hmacSHA256(kService, "aws4_request")
	return kSigning
}

type S3 struct {
	accessKeyID     string
	secretAccessKey string
	region          string
	endpoint        string
	bucket          string
	prefix          string
	linkStyle       string
	timeoutSeconds  int
}

func New(accessKeyID, secretAccessKey, endpoint, region, bucket, prefix, linkStyle string, timeoutSeconds int) *S3 {
	return &S3{
		accessKeyID:     accessKeyID,
		secretAccessKey: secretAccessKey,
		region:          region,
		endpoint:        endpoint,
		bucket:          bucket,
		prefix:          prefix,
		linkStyle:       linkStyle,
		timeoutSeconds:  timeoutSeconds,
	}
}

// Get fetches the object from S3 and writes it to the response writer.
func (s *S3) Get(path string, rw http.ResponseWriter) ([]byte, error) {
	key := s.prefix + path

	urlStr, err := generatePresignedURL(s.accessKeyID, s.secretAccessKey, s.region, s.endpoint, s.bucket, s.linkStyle, key)
	if err != nil {
		http.Error(rw, fmt.Sprintf("unable to generate presigned URL, %v", err), http.StatusInternalServerError)
		return nil, err
	}

	resp, err := http.Get(urlStr)
	if err != nil {
		http.Error(rw, fmt.Sprintf("unable to fetch object from S3, %v", err), http.StatusInternalServerError)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		http.Error(rw, string(body), resp.StatusCode)
		return nil, errors.New("failed to fetch object from S3")
	}

	rw.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	rw.Header().Set("Content-Length", resp.Header.Get("Content-Length"))

	response, err := io.ReadAll(resp.Body)
	return response, err
}
