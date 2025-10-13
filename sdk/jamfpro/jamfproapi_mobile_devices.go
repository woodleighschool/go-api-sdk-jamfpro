// jamfproapi_mobile_devices.go
// Jamf Pro API - Mobile Device Inventory
// API reference:
// Jamf Pro API requires the structs to support a JSON data structure.

/*
Shared resources in this Endpoint:
- SharedResourceSiteProAPI
*/

package jamfpro

import (
	"fmt"
	"net/url"

	"github.com/mitchellh/mapstructure"
)

const uriMobileDevicesInventory = "/api/v2/mobile-devices"

// List

type ResponseMobileDeviceInventoryList struct {
	TotalCount int                             `json:"totalCount"`
	Results    []ResourceMobileDeviceInventory `json:"results"`
}

type ResourceMobileDeviceInventory struct {
	ID                   string                                           `json:"mobileDeviceId"`
	DeviceType           string                                           `json:"deviceType"`
	Hardware             MobileDeviceInventorySubsetHardware              `json:"hardware"`
	UserAndLocation      MobileDeviceInventorySubsetUserAndLocation       `json:"userAndLocation"`
	Applications         []MobileDeviceInventorySubsetApplication         `json:"applications"`
	Certificates         []MobileDeviceInventorySubsetCertificate         `json:"certificates"`
	Profiles             []MobileDeviceInventorySubsetProfile             `json:"profiles"`
	Groups               []MobileDeviceInventorySubsetGroup               `json:"groups"`
	ExtensionAttributes  []MobileDeviceInventorySubsetExtensionAttribute  `json:"extensionAttributes"`
	General              MobileDeviceInventorySubsetGeneral               `json:"general"`
	Security             MobileDeviceInventorySubsetSecurity              `json:"security"`
	EBooks               []MobileDeviceInventorySubsetEBook               `json:"ebooks"`
	Network              MobileDeviceInventorySubsetNetwork               `json:"network"`
	ServiceSubscriptions []MobileDeviceInventorySubsetServiceSubscription `json:"serviceSubscriptions"`
	ProvisioningProfiles []MobileDeviceInventorySubsetProvisioningProfile `json:"provisioningProfiles"`
	SharedUsers          []MobileDeviceInventorySubsetSharedUser          `json:"sharedUsers"`
	Purchasing           MobileDeviceInventorySubsetPurchashing           `json:"purchasing"`
	UserProfiles         []MobileDeviceInventorySubsetUserProfile         `json:"userProfiles"`
}

type MobileDeviceInventorySubsetHardware struct {
	CapacityMB                int    `json:"capacityMB"`
	AvailableSpaceMB          int    `json:"availableSpaceMB"`
	UsedSpacePercentage       int    `json:"usedSpacePercentage"`
	BatteryLevel              int    `json:"batteryLevel"`
	BatteryHealth             string `json:"batteryHealth"`
	SerialNumber              string `json:"serialNumber"`
	WifiMacAddress            string `json:wifiMacAddress"`
	BluetoothMacAddress       string `json:"bluetoothMacAddress"`
	ModemFirmwareVersion      string `json:"modemFirmwareVersion"`
	Model                     string `json:"model"`
	ModelIdentifier           string `json:"modelIdentifier"`
	ModelNumber               string `json:"modelNumber"`
	BluetoothLowEnergyCapable bool   `json:"bluetoothLowEnergyCapable"`
	DeviceID                  string `json:"deviceId"`
	ExtensionAttributes       []MobileDeviceInventorySubsetExtensionAttribute
}

type MobileDeviceInventorySubsetUserAndLocation struct {
	Username            string `json:"username"`
	RealName            string `json:"realName"`
	EmailAddress        string `json:"emailAddress"`
	Position            string `json:"position"`
	PhoneNumber         string `json:"phoneNumber"`
	DepartmentID        string `json:"departmentID"`
	BuildingID          string `json:"buildingID"`
	Room                string `json:"room"`
	Building            string `json:"building"`
	Department          string `json:"department"`
	ExtensionAttributes []MobileDeviceInventorySubsetExtensionAttribute
}

type MobileDeviceInventorySubsetApplication struct {
	Identifier       string `json:"identifier"`
	Name             string `json:"name"`
	Version          string `json:"version"`
	ShortVersion     string `json:"shortVersion"`
	ManagementStatus string `json:"managementStatus"`
	ValidationStatus bool   `json:"validationStatus"`
	BundleSize       string `json:"bundleSize"`
	DynamicSize      string `json:"dynamicSize"`
}

type MobileDeviceInventorySubsetCertificate struct {
	CommonName     string `json:"commonName"`
	Identity       bool   `json:"identity"`
	ExpirationDate string `json:"expirationDate"`
}

type MobileDeviceInventorySubsetProfile struct {
	DisplayName   string `json:"displayName"`
	Version       string `json:"version"`
	UUID          string `json:"uuid"`
	Identifier    string `json:"identifier"`
	Removable     bool   `json:"removable"`
	LastInstalled string `json:"lastInstalled"`
}

type MobileDeviceInventorySubsetGroup struct {
	GroupID          string `json:"groupId"`
	GroupName        string `json:"groupName"`
	GroupDescription string `json:"groupDescription"`
	Smart            bool   `json:"smart"`
}

type MobileDeviceInventorySubsetExtensionAttribute struct {
	ID                                  string   `json:"id"`
	Name                                string   `json:"name"`
	Type                                string   `json:"type"`
	Value                               []string `json:"value"`
	ExtensionAttributeCollectionAllowed bool     `json:"extensionAttributeCollectionAllowed"`
	InventoryDisplay                    string   `json:"inventoryDisplay"`
}

type MobileDeviceInventorySubsetGeneral struct {
	UDID                                        string                                             `json:"udid"`
	DisplayName                                 string                                             `json:"displayName"`
	AssetTag                                    string                                             `json:"assetTag"`
	SiteID                                      string                                             `json:"siteId"`
	LastInventoryUpdateDate                     string                                             `json:"lastInventoryUpdateDate"`
	OSVersion                                   string                                             `json:"osVersion"`
	OSRapidSecurityResponse                     string                                             `json:"osRapidSecurityResponse"`
	OSBuild                                     string                                             `json:"osBuild"`
	OSSupplementalBuildVersion                  string                                             `json:"osSupplementalBuildVersion"`
	SoftwareUpdateDeviceID                      string                                             `json:"softwareUpdateDeviceId"`
	IPAddress                                   string                                             `json:"ipAddress"`
	Managed                                     bool                                               `json:"managed"`
	Supervised                                  bool                                               `json:"supervised"`
	DeviceOwnershipType                         string                                             `json:"deviceOwnershipType"`
	EnrollmentMethodPrestage                    MobileDeviceInventorySubsetGeneralEnrollmentMethod `json:"enrollmentMethodPrestage"`
	EnrollmentSessionTokenValid                 bool                                               `json:"enrollmentSessionTokenValid"`
	LastEnrolledDate                            string                                             `json:"lastEnrolledDate"`
	MDMProfileExpirationDate                    string                                             `json:"mdmProfileExpirationDate"`
	TimeZone                                    string                                             `json:"timeZone"`
	DeclarativeDeviceManagementEnabled          bool                                               `json:"declarativeDeviceManagementEnabled"`
	ManagementID                                string                                             `json:"managementId"`
	ExtensionAttributes                         []MobileDeviceInventorySubsetExtensionAttribute    `json:"extensionAttributes"`
	LastLoggedInUsernameSelfService             string                                             `json:"lastLoggedInUsernameSelfService"`
	LastLoggedInUsernameSelfServiceTimestamp    string                                             `json:"lastLoggedInUsernameSelfServiceTimestamp"`
	SharediPad                                  bool                                               `json:"sharedIpad"`
	DiagnosticAndUsageReportingEnabled          bool                                               `json:"diagnosticAndUsageReportingEnabled"`
	AppAnalyticsEnabled                         bool                                               `json:"appAnalyticsEnabled"`
	ResidentUsers                               int                                                `json:"residentUsers"`
	QuotaSize                                   int                                                `json:"quotaSize"`
	TemporarySessionOnly                        bool                                               `json:"temporarySessionOnly"`
	TemporarySessionTimeout                     int                                                `json:"temporarySessionTimeout"`
	UserSessionTimeout                          int                                                `json:"userSessionTimeout"`
	SyncedToComputer                            int                                                `json:"syncedToComputer"`
	MaximumSharediPadUsersStored                int                                                `json:"maximumSharediPadUsersStored"`
	LastBackupDate                              string                                             `json:"lastBackupDate"`
	DeviceLocatorServiceEnabled                 bool                                               `json:"deviceLocatorServiceEnabled"`
	DoNotDisturbEnabled                         bool                                               `json:"doNotDisturbEnabled"`
	CloudBackupEnabled                          bool                                               `json:"cloudBackupEnabled"`
	LastCloudBackupDate                         string                                             `json:"lastCloudBackupDate"`
	LocationServicesForSelfServiceMobileEnabled bool                                               `json:"locationServicesForSelfServiceMobileEnabled"`
	ITunesStoreAccountActive                    bool                                               `json:"itunesStoreAccountActive"`
	ExchangeDeviceID                            string                                             `json:"exchangeDeviceId"`
	Tethered                                    bool                                               `json:"tethered"`
}

type MobileDeviceInventorySubsetGeneralEnrollmentMethod struct {
	MobileDevicePrestageID string `json:"mobileDevicePrestageId"`
	ProfileName            string `json:"profileName"`
}

type MobileDeviceInventorySubsetSecurity struct {
	DataProtected                          bool                                        `json:"dataProtected"`
	BlockLevelEncryptionCapable            bool                                        `json:"blockLevelEncryptionCapable"`
	FileLevelEncryptionCapable             bool                                        `json:"fileLevelEncryptionCapable"`
	PasscodePresent                        bool                                        `json:"passcodePresent"`
	PasscodeCompliant                      bool                                        `json:"passcodeCompliant"`
	PasscodeCompliantWithProfile           bool                                        `json:"passcodeCompliantWithProfile"`
	HardwareEncryption                     int                                         `json:"hardwareEncryption"`
	ActivationLockEnabled                  int                                         `json:"activationLockEnabled"`
	JailBreakDetected                      int                                         `json:"jailBreakDetected"`
	AttestationStatus                      string                                      `json:"attestationStatus"`
	LastAttestationAttemptDate             string                                      `json:"lastAttestationAttemptDate"`
	LastSuccessfulAttestationDate          string                                      `json:"lastSuccessfulAttestationDate"`
	PasscodeLockGracePeriodEnforcedSeconds int                                         `json:"passcodeLockGracePeriodEnforcedSeconds"`
	PersonalDeviceProfileCurrent           bool                                        `json:"personalDeviceProfileCurrent"`
	LostModeEnabled                        bool                                        `json:"lostModeEnabled"`
	LostModePersistent                     bool                                        `json:"lostModePersistent"`
	LostModeMessage                        string                                      `json:"lostModeMessage"`
	LostModePhoneNumber                    string                                      `json:"lostModePhoneNumber"`
	LostModeFootnote                       string                                      `json:"lostModeFootnote"`
	LostModeLocation                       MobileDeviceInventorySubsetSecurityLocation `json:"lostModeLocation"`
	BootstraoTokenEscrowed                 string                                      `json:"bootstrapTokenEscrowed"`
}

type MobileDeviceInventorySubsetSecurityLocation struct {
	LastLocationUpdate                       string `json:"lastLocationUpdate"`
	LostModeLocationHorizontalAccuracyMeters int    `json:"lostModeLocationHorizontalAccuracyMeters"`
	LostModeLocationVerticalAccuracyMeters   int    `json:"lostModeLocationVerticalAccuracyMeters"`
	LostModeLocationAltitudeMeters           int    `json:"lostModeLocationAltitudeMeters"`
	LostModeLocationSpeedMetersPerSecond     int    `json:"lostModeLocationSpeedMetersPerSecond"`
	LostModeLocationCourseDegrees            int    `json:"lostModeLocationCourseDegrees"`
	LostModeLocationTimestamp                string `json:"lostModeLocationTimestamp"`
}

type MobileDeviceInventorySubsetEBook struct {
	Author          string `json:"author"`
	Title           string `json:"title"`
	Version         string `json:"version"`
	Kind            string `json:"kind"`
	ManagementState string `json:"managementState"`
}

type MobileDeviceInventorySubsetNetwork struct {
	CellularTechnology       string `json:"cellularTechnology"`
	VoiceRoamingEnabled      bool   `json:"voiceRoamingEnabled"`
	IMEI                     string `json:"imei"`
	ICCID                    string `json:"iccid"`
	MEID                     string `json:"meid"`
	EID                      string `json:"eid"`
	CarrierSettingsVersion   string `json:"carrierSettingsVersion"`
	CurrentCarrierNetwork    string `json:"currentCarrierNetwork"`
	CurrentMobileCountryCode string `json:"currentMobileCountryCode"`
	CurrentMobileNetworkCode string `json:"currentMobileNetworkCode"`
	HomeCarrierNetwork       string `json:"homeCarrierNetwork"`
	HomeMobileCountryCode    string `json:"homeMobileCountryCode"`
	HomeMobileNetworkCode    string `json:"homeMobileNetworkCode"`
	DataRoamingEnabled       bool   `json:"dataRoamingEnabled"`
	Roaming                  bool   `json:"roaming"`
	PersonalHotspotEnabled   bool   `json:"personalHotspotEnabled"`
	PhoneNumber              string `json:"phoneNumber"`
	PreferredVoiceNumber     string `json:"preferredVoiceNumber"`
}

type MobileDeviceInventorySubsetServiceSubscription struct {
	CarrierSettingsVersion   string `json:"carrierSettingsVersion"`
	CurrentCarrierNetwork    string `json:"currentCarrierNetwork"`
	CurrentMobileCountryCode string `json:"currentMobileCountryCode"`
	CurrentMobileNetworkCode string `json:"currentMobileNetworkCode"`
	SubscriberCarrierNetwork string `json:"subscriberCarrierNetwork"`
	EID                      string `json:"eid"`
	ICCID                    string `json:"iccid"`
	IMEI                     string `json:"imei"`
	DataPreferred            bool   `json:"dataPreferred"`
	Roaming                  bool   `json:"roaming"`
	VoicePreferred           bool   `json:"voicePreferred"`
	Label                    string `json:"label"`
	LabelID                  string `json:"labelId"`
	MEID                     string `json:"meid"`
	PhoneNumber              string `json:"phoneNumber"`
	Slot                     string `json:"slot"`
}

type MobileDeviceInventorySubsetProvisioningProfile struct {
	DisplayName    string `json:"displayName"`
	UUID           string `json:"uuid"`
	ExpirationDate string `json:"expirationDate"`
}

type MobileDeviceInventorySubsetSharedUser struct {
	ManagedAppleID string `json:"managedAppleId"`
	LoggedIn       bool   `json:"loggedIn"`
	DataToSync     bool   `json:"dataToSync"`
}

type MobileDeviceInventorySubsetPurchashing struct {
	Purchased           bool                                            `json:"purchased"`
	Leased              bool                                            `json:"leased"`
	PONumber            string                                          `json:"poNumber"`
	Vendor              string                                          `json:"vendor"`
	AppleCareID         string                                          `json:"appleCareId"`
	PurchasePrice       string                                          `json:"purchasePrice"`
	PurchasingAccount   string                                          `json:"purchasingAccount"`
	PODate              string                                          `json:"poDate"`
	WarrantyExpiresDate string                                          `json:"warrantyExpiresDate"`
	LeaseExpiresData    string                                          `json:"leaseExpiresDate"`
	LifeExpectancy      int                                             `json:"lifeExpectancy"`
	PurchasingContact   string                                          `json:"purchasingContact"`
	ExtensionAttributes []MobileDeviceInventorySubsetExtensionAttribute `json:"extensionAttributes"`
}

type MobileDeviceInventorySubsetUserProfile struct {
	DisplayName   string `json:"displayName"`
	Version       string `json:"version"`
	UUID          string `json:"uuid"`
	Identifier    string `json:"identifier"`
	Removable     bool   `json:"removable"`
	LastInstalled string `json:"lastInstalled"`
	Username      string `json:"username"`
}

func (c *Client) GetMobileDevicesInventory(params url.Values) (*ResponseMobileDeviceInventoryList, error) {
	resp, err := c.DoPaginatedGet(uriMobileDevices, params)

	if err != nil {
		return nil, fmt.Errorf(errMsgFailedPaginatedGet, "mobile-devices", err)
	}

	var out ResponseMobileDeviceInventoryList
	out.TotalCount = resp.Size

	for _, value := range resp.Results {
		var newObj ResourceMobileDeviceInventory
		err := mapstructure.Decode(value, &newObj)
		if err != nil {
			return nil, fmt.Errorf(errMsgFailedMapstruct, "mobile-device", err)
		}
		out.Results = append(out.Results, newObj)
	}

	return &out, nil
}

func (c *Client) GetMobileDeviceInventoryByID(id string) (*ResourceMobileDeviceInventory, error) {
	endpoint := fmt.Sprintf("%s/%s", uriMobileDevices, id)

	var responseInventory ResourceMobileDeviceInventory
	resp, err := c.HTTP.DoRequest("GET", endpoint, nil, &responseInventory)
	if err != nil {
		return nil, fmt.Errorf(errMsgFailedGetByID, "mobile device inventory", id, err)
	}

	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	return &responseInventory, nil

}

func (c *Client) GetMobileDeviceInventoryByName(name string) (*ResourceMobileDeviceInventory, error) {
	inventories, err := c.GetMobileDevicesInventory(nil)
	if err != nil {
		return nil, fmt.Errorf(errMsgFailedPaginatedGet, "mobile devices inventory", err)
	}

	for _, inventory := range inventories.Results {
		if inventory.General.DisplayName == name {
			return &inventory, nil
		}
	}

	return nil, fmt.Errorf(errMsgFailedGetByName, "mobile devices inventory", name, err)
}

func (c *Client) UpdateMobileDeviceInventoryByID(id string, inventoryUpdate *ResourceMobileDeviceInventory) (*ResourceMobileDeviceInventory, error) {
	endpoint := fmt.Sprintf("%s/%s", uriMobileDevicesInventory, id)

	var updatedInventory ResourceMobileDeviceInventory
	resp, err := c.HTTP.DoRequest("PATCH", endpoint, inventoryUpdate, &updatedInventory)
	if err != nil {
		return nil, fmt.Errorf(errMsgFailedUpdateByID, "mobile device inventory", id, err)
	}

	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	return &updatedInventory, nil
}

func (c *Client) EraseMobileDeviceInventoryByID(id string) error {
	return nil
}

func (c *Client) UnmanageMobileDevicInventoryByID(id string) error {
	return nil
}
