// Package classify decides which fields hold personal data, with an Indian
// focus (Aadhaar, PAN, UPI, ABHA, GSTIN, IFSC, voter ID...). It works on
// field and store names only; it never reads data values from databases.
package classify

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/Breaktroughf1/dpdpward/internal/model"
)

// Tokens splits an identifier into lower-case words:
// "guardianPhoneNo" -> [guardian phone no], "date_of_birth" -> [date of birth].
func Tokens(s string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(s)
	for i, r := range rs {
		switch {
		case r == '_' || r == '-' || r == ' ' || r == '.':
			flush()
		case unicode.IsUpper(r):
			// New word at a lower->upper boundary, or at the last capital of
			// an acronym followed by lower case ("IFSCCode" -> ifsc code).
			if len(cur) > 0 && (unicode.IsLower(rs[i-1]) || unicode.IsDigit(rs[i-1]) ||
				(i+1 < len(rs) && unicode.IsLower(rs[i+1]) && unicode.IsUpper(rs[i-1]))) {
				flush()
			}
			cur = append(cur, r)
		case unicode.IsDigit(r):
			if len(cur) > 0 && !unicode.IsDigit(rs[i-1]) {
				flush()
			}
			cur = append(cur, r)
		default:
			if len(cur) > 0 && unicode.IsDigit(rs[i-1]) {
				flush()
			}
			cur = append(cur, r)
		}
	}
	flush()
	return out
}

type rule struct {
	category, label, sens, conf string
	children                    bool
	// any: one of these tokens present; all: every token present;
	// joined: substring of the concatenated tokens.
	any, all, joined []string
	personOnly       bool // only on person-like stores
}

var rules = []rule{
	{category: "government-id.aadhaar", label: "Aadhaar number", sens: model.SensHigh, conf: "high", joined: []string{"aadhaar", "aadhar", "uidai"}},
	{category: "government-id.pan", label: "PAN (tax ID or payment card number)", sens: model.SensHigh, conf: "high", any: []string{"pan"}},
	{category: "government-id.passport", label: "Passport number", sens: model.SensHigh, conf: "high", any: []string{"passport"}},
	{category: "government-id.voter-id", label: "Voter ID (EPIC)", sens: model.SensHigh, conf: "high", any: []string{"epic", "voter", "voterid"}},
	{category: "government-id.driving-licence", label: "Driving licence number", sens: model.SensHigh, conf: "high", joined: []string{"drivinglicen", "drivinglicence", "dlnumber", "dlno"}},
	{category: "health.abha", label: "ABHA / health ID", sens: model.SensHigh, conf: "high", joined: []string{"abha", "healthid", "uhid"}},
	{category: "business-id.gstin", label: "GSTIN", sens: model.SensMedium, conf: "high", any: []string{"gstin", "gst"}},
	{category: "financial.card-security-code", label: "Card CVV / PIN", sens: model.SensHigh, conf: "high", any: []string{"cvv", "cvc", "cvv2"}, joined: []string{"cardpin", "atmpin"}},
	{category: "financial.card-number", label: "Payment card number", sens: model.SensHigh, conf: "high", joined: []string{"cardnumber", "cardno", "creditcard", "debitcard", "ccnumber"}},
	{category: "financial.upi", label: "UPI ID (VPA)", sens: model.SensHigh, conf: "high", any: []string{"upi", "vpa"}},
	{category: "financial.bank-account", label: "Bank account number", sens: model.SensHigh, conf: "high", joined: []string{"accountnumber", "accountno", "acctno", "acctnumber", "bankaccount", "iban"}},
	{category: "financial.ifsc", label: "IFSC code", sens: model.SensMedium, conf: "high", any: []string{"ifsc"}},
	{category: "financial.income", label: "Income / credit information", sens: model.SensMedium, conf: "medium", any: []string{"salary", "income", "cibil", "networth"}, joined: []string{"creditscore"}},
	{category: "biometric", label: "Biometric data", sens: model.SensHigh, conf: "high", any: []string{"biometric", "fingerprint", "iris", "retina", "faceprint", "voiceprint"}, joined: []string{"facedata", "faceembedding", "faceid"}},
	{category: "health", label: "Health data", sens: model.SensHigh, conf: "medium", any: []string{"diagnosis", "medical", "prescription", "disease", "allergy", "allergies", "medication", "symptoms", "disability", "pregnancy"}, joined: []string{"bloodgroup", "bloodtype", "healthrecord", "healthcondition"}},
	{category: "sensitive.demographic", label: "Religion, caste or similar", sens: model.SensHigh, conf: "medium", any: []string{"religion", "caste", "ethnicity", "tribe"}, joined: []string{"sexualorientation", "politicalview", "politicalaffiliation"}},
	{category: "identity.gender", label: "Gender", sens: model.SensMedium, conf: "medium", any: []string{"gender", "sex"}},
	{category: "identity.dob", label: "Date of birth / age", sens: model.SensMedium, conf: "high", children: true, any: []string{"dob", "birthday", "birthdate", "age"}, joined: []string{"dateofbirth", "birthdate"}},
	{category: "children.guardian", label: "Parent / guardian details", sens: model.SensMedium, conf: "medium", children: true, any: []string{"guardian", "minor"}, joined: []string{"parentconsent", "parentname", "parentphone", "parentemail", "isminor", "ischild"}},
	{category: "contact.email", label: "Email address", sens: model.SensMedium, conf: "high", any: []string{"email", "mail"}},
	{category: "contact.phone", label: "Phone number", sens: model.SensMedium, conf: "high", any: []string{"phone", "mobile", "msisdn", "whatsapp", "telephone"}, joined: []string{"contactnumber", "contactno", "phoneno"}},
	{category: "identity.name", label: "Person's name", sens: model.SensMedium, conf: "high", joined: []string{"firstname", "lastname", "fullname", "middlename", "surname", "givenname", "familyname", "fathername", "mothername", "spousename", "nominee"}},
	{category: "identity.name", label: "Person's name", sens: model.SensMedium, conf: "medium", any: []string{"name"}, personOnly: true},
	{category: "online.identifier", label: "Device or network identifier", sens: model.SensLow, conf: "medium", any: []string{"imei", "ip"}, joined: []string{"ipaddress", "deviceid", "advertisingid", "gaid", "idfa", "useragent", "cookieid", "macaddress"}},
	{category: "location.address", label: "Postal address", sens: model.SensMedium, conf: "high", any: []string{"address", "street", "pincode", "postcode", "zipcode", "landmark", "locality"}, joined: []string{"pincode", "postalcode", "addressline"}},
	{category: "location.precise", label: "Precise location", sens: model.SensMedium, conf: "medium", any: []string{"latitude", "longitude", "geolocation", "gps"}, joined: []string{"latlng", "latlong", "geopoint"}},
	{category: "identity.photo", label: "Photograph / selfie", sens: model.SensMedium, conf: "medium", any: []string{"selfie", "photo", "photograph", "avatar"}},
	{category: "credential", label: "Credential (password, OTP, PIN)", sens: model.SensHigh, conf: "medium", any: []string{"password", "passwd", "otp", "passcode", "mpin"}},
	{category: "employment", label: "Employment record", sens: model.SensLow, conf: "low", any: []string{"designation", "employer", "occupation"}, joined: []string{"employeeid", "employeecode"}},
}

// personStore matches store names that hold records about people, used to
// decide whether a bare "name" column is a person's name.
var personStore = regexp.MustCompile(`(?i)(user|customer|client|member|patient|student|employee|staff|person|people|profile|contact|guardian|parent|applicant|borrower|lender|citizen|child|voter|account|subscriber|candidate|beneficiar|nominee|driver|rider|passenger|tenant|buyer|seller|vendor|teacher|doctor|guest|lead|kyc)`)

// lastTokenNotValue: when the final token is one of these, the column is
// metadata about the data, e.g. email_verified, phone_verified_at.
var lastTokenNotValue = map[string]bool{"verified": true, "at": true, "count": true, "flag": true, "enabled": true,
	"status": true, "type": true, "template": true, "format": true, "regex": true, "label": true, "sent": true,
	"attempts": true, "valid": true, "verification": true, "visible": true, "public": true, "required": true}

// boolTypes are column types that cannot hold the personal data itself.
var boolTypes = map[string]bool{"bool": true, "boolean": true, "booleanfield": true, "bit": true, "tinyint(1)": true}

// Field classifies one field of a store. It returns nil when the field does
// not look like personal data.
func Field(s model.Store, f model.Field) *model.Element {
	toks := Tokens(f.Name)
	if len(toks) == 0 {
		return nil
	}
	if boolTypes[strings.ToLower(f.Type)] {
		return nil
	}
	if toks[0] == "is" || toks[0] == "has" || lastTokenNotValue[toks[len(toks)-1]] {
		// "dob" is a value even though "is_minor" is metadata: keep children
		// indicators, which matter even as flags.
		if !(len(toks) >= 2 && (toks[1] == "minor" || toks[1] == "child")) {
			return nil
		}
	}
	joined := strings.Join(toks, "")
	set := map[string]bool{}
	for _, t := range toks {
		set[t] = true
	}
	for _, r := range rules {
		if r.personOnly && !(personStore.MatchString(s.Name) && len(toks) == 1) {
			continue
		}
		hit, why := match(r, set, joined)
		if !hit {
			continue
		}
		// "pan" inside "company" etc. is excluded by token matching; but a
		// "pan" column on a pan-India lookup, e.g. pan_india, is not a PAN.
		if r.category == "government-id.pan" && (set["india"] || set["tilt"] || set["zoom"]) {
			continue
		}
		if r.category == "identity.dob" && set["age"] && (set["page"] || set["usage"] || set["storage"] || set["average"] || set["image"]) {
			continue
		}
		e := &model.Element{Store: s.Name, StoreKind: s.Kind, Field: f.Name, File: s.File, Line: f.Line,
			Category: r.category, Label: r.label, Sensitivity: r.sens, Confidence: r.conf, Reason: why}
		e.Children = r.children
		return e
	}
	return nil
}

func match(r rule, set map[string]bool, joined string) (bool, string) {
	for _, a := range r.any {
		if set[a] {
			return true, "field name contains \"" + a + "\""
		}
	}
	for _, j := range r.joined {
		if strings.Contains(joined, j) {
			return true, "field name matches \"" + j + "\""
		}
	}
	if len(r.all) > 0 {
		for _, a := range r.all {
			if !set[a] {
				return false, ""
			}
		}
		return true, "field name contains " + strings.Join(r.all, "+")
	}
	return false, ""
}

// Stores classifies every field of every store.
func Stores(stores []model.Store) []model.Element {
	var out []model.Element
	for _, s := range stores {
		for _, f := range s.Fields {
			if e := Field(s, f); e != nil {
				out = append(out, *e)
			}
		}
	}
	return out
}
