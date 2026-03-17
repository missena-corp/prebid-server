package gdpr

import (
	"errors"
	"fmt"
	"strings"

	"github.com/prebid/go-gdpr/api"
	"github.com/prebid/go-gdpr/vendorconsent"
	tcf2 "github.com/prebid/go-gdpr/vendorconsent/tcf2"
)

// parsedConsent represents a parsed consent string containing notable version information and a convenient
// metadata object that allows easy examination of encoded purpose and vendor information
type parsedConsent struct {
	encodingVersion uint8
	listVersion     uint16
	specVersion     uint16
	consentMeta     tcf2.ConsentMetadata
}

// sanitizeConsentString fixes consent strings where base64url segments have an
// invalid length (1 mod 4). Some CMPs produce consent strings where a segment
// length is not valid for standard base64 decoding. TCF consent strings are
// bit-level encodings where each base64url character represents 6 bits. When
// the total number of bits is not aligned to byte boundaries, the segment
// length can end up as 1 mod 4 which Go's base64 decoder rejects. Padding
// with 'A' (zero bits) to the next valid length preserves all original data.
func sanitizeConsentString(consent string) string {
	segments := strings.Split(consent, ".")
	changed := false
	for i, seg := range segments {
		if len(seg) > 0 && len(seg)%4 == 1 {
			segments[i] = seg + "AAA"
			changed = true
		}
	}
	if changed {
		return strings.Join(segments, ".")
	}
	return consent
}

// parseConsent parses and validates the specified consent string returning an instance of parsedConsent
func parseConsent(consent string) (*parsedConsent, error) {
	consent = sanitizeConsentString(consent)
	pc, err := vendorconsent.ParseString(consent)
	if err != nil {
		return nil, &ErrorMalformedConsent{
			Consent: consent,
			Cause:   err,
		}
	}
	if err = validateVersions(pc); err != nil {
		return nil, &ErrorMalformedConsent{
			Consent: consent,
			Cause:   err,
		}
	}
	cm, ok := pc.(tcf2.ConsentMetadata)
	if !ok {
		err = errors.New("Unable to access TCF2 parsed consent")
		return nil, err
	}
	return &parsedConsent{
		encodingVersion: pc.Version(),
		listVersion:     pc.VendorListVersion(),
		specVersion:     getSpecVersion(pc.TCFPolicyVersion()),
		consentMeta:     cm,
	}, nil
}

// validateVersions ensures that certain version fields in the consent string contain valid values.
// An error is returned if at least one of them is invalid
func validateVersions(pc api.VendorConsents) (err error) {
	version := pc.Version()
	if version != 2 {
		return fmt.Errorf("invalid encoding format version: %d", version)
	}
	return
}

// getSpecVersion looks at the TCF policy version and determines the corresponding GVL specification
// version that should be used to calculate legal basis. A zero value is returned if the policy version
// is invalid
func getSpecVersion(policyVersion uint8) uint16 {
	if policyVersion >= 4 {
		return 3
	}
	return 2
}
