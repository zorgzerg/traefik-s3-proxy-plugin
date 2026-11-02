package s3

import (
	"context"
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

var corsResponseHeaders = []string{
	"Access-Control-Allow-Origin",
	"Access-Control-Allow-Methods",
	"Access-Control-Allow-Headers",
	"Access-Control-Expose-Headers",
	"Access-Control-Max-Age",
	"Access-Control-Allow-Credentials",
	"Vary",
}

func generatePresignedURL(accessKeyID, secretAccessKey, region, endpoint, bucket, linkStyle, key string) (string, error) {
	escapedKey := escapeS3ObjectKey(key)

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

func escapeS3ObjectKey(key string) string {
	var b strings.Builder
	b.Grow(len(key) * 3)

	for i := 0; i < len(key); i++ {
		c := key[i]

		if c == '/' || isUnreserved(c) {
			b.WriteByte(c)
			continue
		}

		b.WriteByte('%')
		b.WriteByte("0123456789ABCDEF"[c>>4])
		b.WriteByte("0123456789ABCDEF"[c&0x0F])
	}

	return b.String()
}

func isUnreserved(c byte) bool {
	return ('A' <= c && c <= 'Z') ||
		('a' <= c && c <= 'z') ||
		('0' <= c && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
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
	client          *http.Client
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
		client: &http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		},
	}
}

// Get fetches the object from S3 and writes it to the response writer.
func (s *S3) Get(ctx context.Context, path, origin string, rw http.ResponseWriter) ([]byte, error) {
	key := s.prefix + path

	urlStr, err := generatePresignedURL(s.accessKeyID, s.secretAccessKey, s.region, s.endpoint, s.bucket, s.linkStyle, key)
	if err != nil {
		http.Error(rw, "unable to generate presigned URL", http.StatusInternalServerError)
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		http.Error(rw, "unable to create S3 request", http.StatusInternalServerError)
		return nil, errors.New("unable to create S3 request")
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		http.Error(rw, "unable to fetch object from S3", http.StatusInternalServerError)
		return nil, errors.New("unable to fetch object from S3")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(rw, http.StatusText(resp.StatusCode), resp.StatusCode)
		return nil, errors.New("failed to fetch object from S3")
	}

	response, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(rw, "unable to read object from S3", http.StatusBadGateway)
		return nil, errors.New("unable to read object from S3")
	}

	rw.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		rw.Header().Set("Content-Length", contentLength)
	}
	copyResponseHeaders(rw.Header(), resp.Header, corsResponseHeaders)

	return response, nil
}

func copyResponseHeaders(dst, src http.Header, names []string) {
	for _, name := range names {
		values := src.Values(name)
		if len(values) == 0 {
			continue
		}

		dst.Del(name)
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}
