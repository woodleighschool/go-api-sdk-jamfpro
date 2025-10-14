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
	ID                   *string                                           `json:"mobileDeviceId,omitempty"`
	DeviceType           *string                                           `json:"deviceType,omitempty"`
	Hardware             *MobileDeviceInventorySubsetHardware              `json:"hardware,omitempty"`
	UserAndLocation      *MobileDeviceInventorySubsetUserAndLocation       `json:"userAndLocation,omitempty"`
	Applications         []*MobileDeviceInventorySubsetApplication         `json:"applications,omitempty"`
	Certificates         []*MobileDeviceInventorySubsetCertificate         `json:"certificates,omitempty"`
	Profiles             []*MobileDeviceInventorySubsetProfile             `json:"profiles,omitempty"`
	Groups               []*MobileDeviceInventorySubsetGroup               `json:"groups,omitempty"`
	ExtensionAttributes  []*MobileDeviceInventorySubsetExtensionAttribute  `json:"extensionAttributes,omitempty"`
	General              *MobileDeviceInventorySubsetGeneral               `json:"general,omitempty"`
	Security             *MobileDeviceInventorySubsetSecurity              `json:"security,omitempty"`
	EBooks               []*MobileDeviceInventorySubsetEBook               `json:"ebooks,omitempty"`
	Network              *MobileDeviceInventorySubsetNetwork               `json:"network,omitempty"`
	ServiceSubscriptions []*MobileDeviceInventorySubsetServiceSubscription `json:"serviceSubscriptions,omitempty"`
	ProvisioningProfiles []*MobileDeviceInventorySubsetProvisioningProfile `json:"provisioningProfiles,omitempty"`
	SharedUsers          []*MobileDeviceInventorySubsetSharedUser          `json:"sharedUsers,omitempty"`
	Purchasing           *MobileDeviceInventorySubsetPurchashing           `json:"purchasing,omitempty"`
	UserProfiles         []*MobileDeviceInventorySubsetUserProfile         `json:"userProfiles,omitempty"`
}

type MobileDeviceInventorySubsetHardware struct {
	CapacityMB                *int    `json:"capacityMB,omitempty"`
	AvailableSpaceMB          *int    `json:"availableSpaceMB,omitempty"`
	UsedSpacePercentage       *int    `json:"usedSpacePercentage,omitempty"`
	BatteryLevel              *int    `json:"batteryLevel,omitempty"`
	BatteryHealth             *string `json:"batteryHealth,omitempty"`
	SerialNumber              *string `json:"serialNumber,omitempty"`
	WifiMacAddress            *string `json:"wifiMacAddress,omitempty"`
	BluetoothMacAddress       *string `json:"bluetoothMacAddress,omitempty"`
	ModemFirmwareVersion      *string `json:"modemFirmwareVersion,omitempty"`
	Model                     *string `json:"model,omitempty"`
	ModelIdentifier           *string `json:"modelIdentifier,omitempty"`
	ModelNumber               *string `json:"modelNumber,omitempty"`
	BluetoothLowEnergyCapable *bool   `json:"bluetoothLowEnergyCapable,omitempty"`
	DeviceID                  *string `json:"deviceId,omitempty"`
	ExtensionAttributes       []*MobileDeviceInventorySubsetExtensionAttribute
}

type MobileDeviceInventorySubsetUserAndLocation struct {
	Username            *string `json:"username,omitempty"`
	RealName            *string `json:"realName,omitempty"`
	EmailAddress        *string `json:"emailAddress,omitempty"`
	Position            *string `json:"position,omitempty"`
	PhoneNumber         *string `json:"phoneNumber,omitempty"`
	DepartmentID        *string `json:"departmentID,omitempty"`
	BuildingID          *string `json:"buildingID,omitempty"`
	Room                *string `json:"room,omitempty"`
	Building            *string `json:"building,omitempty"`
	Department          *string `json:"department,omitempty"`
	ExtensionAttributes []*MobileDeviceInventorySubsetExtensionAttribute
}

type MobileDeviceInventorySubsetApplication struct {
	Identifier       *string `json:"identifier,omitempty"`
	Name             *string `json:"name,omitempty"`
	Version          *string `json:"version,omitempty"`
	ShortVersion     *string `json:"shortVersion,omitempty"`
	ManagementStatus *string `json:"managementStatus,omitempty"`
	ValidationStatus *bool   `json:"validationStatus,omitempty"`
	BundleSize       *string `json:"bundleSize,omitempty"`
	DynamicSize      *string `json:"dynamicSize,omitempty"`
}

type MobileDeviceInventorySubsetCertificate struct {
	CommonName     *string `json:"commonName,omitempty"`
	Identity       *bool   `json:"identity,omitempty"`
	ExpirationDate *string `json:"expirationDate,omitempty"`
}

type MobileDeviceInventorySubsetProfile struct {
	DisplayName   *string `json:"displayName,omitempty"`
	Version       *string `json:"version,omitempty"`
	UUID          *string `json:"uuid,omitempty"`
	Identifier    *string `json:"identifier,omitempty"`
	Removable     *bool   `json:"removable,omitempty"`
	LastInstalled *string `json:"lastInstalled,omitempty"`
}

type MobileDeviceInventorySubsetGroup struct {
	GroupID          *string `json:"groupId,omitempty"`
	GroupName        *string `json:"groupName,omitempty"`
	GroupDescription *string `json:"groupDescription,omitempty"`
	Smart            *bool   `json:"smart,omitempty"`
}

type MobileDeviceInventorySubsetExtensionAttribute struct {
	ID                                  *string   `json:"id,omitempty"`
	Name                                *string   `json:"name,omitempty"`
	Type                                *string   `json:"type,omitempty"`
	Value                               []*string `json:"value,omitempty"`
	ExtensionAttributeCollectionAllowed *bool     `json:"extensionAttributeCollectionAllowed,omitempty"`
	InventoryDisplay                    *string   `json:"inventoryDisplay,omitempty"`
}

type MobileDeviceInventorySubsetGeneral struct {
	UDID                                        *string                                             `json:"udid,omitempty"`
	DisplayName                                 *string                                             `json:"displayName,omitempty"`
	AssetTag                                    *string                                             `json:"assetTag,omitempty"`
	SiteID                                      *string                                             `json:"siteId,omitempty"`
	LastInventoryUpdateDate                     *string                                             `json:"lastInventoryUpdateDate,omitempty"`
	OSVersion                                   *string                                             `json:"osVersion,omitempty"`
	OSRapidSecurityResponse                     *string                                             `json:"osRapidSecurityResponse,omitempty"`
	OSBuild                                     *string                                             `json:"osBuild,omitempty"`
	OSSupplementalBuildVersion                  *string                                             `json:"osSupplementalBuildVersion,omitempty"`
	SoftwareUpdateDeviceID                      *string                                             `json:"softwareUpdateDeviceId,omitempty"`
	IPAddress                                   *string                                             `json:"ipAddress,omitempty"`
	Managed                                     *bool                                               `json:"managed,omitempty"`
	Supervised                                  *bool                                               `json:"supervised,omitempty"`
	DeviceOwnershipType                         *string                                             `json:"deviceOwnershipType,omitempty"`
	EnrollmentMethodPrestage                    *MobileDeviceInventorySubsetGeneralEnrollmentMethod `json:"enrollmentMethodPrestage,omitempty"`
	EnrollmentSessionTokenValid                 *bool                                               `json:"enrollmentSessionTokenValid,omitempty"`
	LastEnrolledDate                            *string                                             `json:"lastEnrolledDate,omitempty"`
	MDMProfileExpirationDate                    *string                                             `json:"mdmProfileExpirationDate,omitempty"`
	TimeZone                                    *string                                             `json:"timeZone,omitempty"`
	DeclarativeDeviceManagementEnabled          *bool                                               `json:"declarativeDeviceManagementEnabled,omitempty"`
	ManagementID                                *string                                             `json:"managementId,omitempty"`
	ExtensionAttributes                         []*MobileDeviceInventorySubsetExtensionAttribute    `json:"extensionAttributes,omitempty"`
	LastLoggedInUsernameSelfService             *string                                             `json:"lastLoggedInUsernameSelfService,omitempty"`
	LastLoggedInUsernameSelfServiceTimestamp    *string                                             `json:"lastLoggedInUsernameSelfServiceTimestamp,omitempty"`
	SharediPad                                  *bool                                               `json:"sharedIpad,omitempty"`
	DiagnosticAndUsageReportingEnabled          *bool                                               `json:"diagnosticAndUsageReportingEnabled,omitempty"`
	AppAnalyticsEnabled                         *bool                                               `json:"appAnalyticsEnabled,omitempty"`
	ResidentUsers                               *int                                                `json:"residentUsers,omitempty"`
	QuotaSize                                   *int                                                `json:"quotaSize,omitempty"`
	TemporarySessionOnly                        *bool                                               `json:"temporarySessionOnly,omitempty"`
	TemporarySessionTimeout                     *int                                                `json:"temporarySessionTimeout,omitempty"`
	UserSessionTimeout                          *int                                                `json:"userSessionTimeout,omitempty"`
	SyncedToComputer                            *int                                                `json:"syncedToComputer,omitempty"`
	MaximumSharediPadUsersStored                *int                                                `json:"maximumSharediPadUsersStored,omitempty"`
	LastBackupDate                              *string                                             `json:"lastBackupDate,omitempty"`
	DeviceLocatorServiceEnabled                 *bool                                               `json:"deviceLocatorServiceEnabled,omitempty"`
	DoNotDisturbEnabled                         *bool                                               `json:"doNotDisturbEnabled,omitempty"`
	CloudBackupEnabled                          *bool                                               `json:"cloudBackupEnabled,omitempty"`
	LastCloudBackupDate                         *string                                             `json:"lastCloudBackupDate,omitempty"`
	LocationServicesForSelfServiceMobileEnabled *bool                                               `json:"locationServicesForSelfServiceMobileEnabled,omitempty"`
	ITunesStoreAccountActive                    *bool                                               `json:"itunesStoreAccountActive,omitempty"`
	ExchangeDeviceID                            *string                                             `json:"exchangeDeviceId,omitempty"`
	Tethered                                    *bool                                               `json:"tethered,omitempty"`
}

type MobileDeviceInventorySubsetGeneralEnrollmentMethod struct {
	MobileDevicePrestageID *string `json:"mobileDevicePrestageId,omitempty"`
	ProfileName            *string `json:"profileName,omitempty"`
}

type MobileDeviceInventorySubsetSecurity struct {
	DataProtected                          *bool                                        `json:"dataProtected,omitempty"`
	BlockLevelEncryptionCapable            *bool                                        `json:"blockLevelEncryptionCapable,omitempty"`
	FileLevelEncryptionCapable             *bool                                        `json:"fileLevelEncryptionCapable,omitempty"`
	PasscodePresent                        *bool                                        `json:"passcodePresent,omitempty"`
	PasscodeCompliant                      *bool                                        `json:"passcodeCompliant,omitempty"`
	PasscodeCompliantWithProfile           *bool                                        `json:"passcodeCompliantWithProfile,omitempty"`
	HardwareEncryption                     *int                                         `json:"hardwareEncryption,omitempty"`
	ActivationLockEnabled                  *int                                         `json:"activationLockEnabled,omitempty"`
	JailBreakDetected                      *int                                         `json:"jailBreakDetected,omitempty"`
	AttestationStatus                      *string                                      `json:"attestationStatus,omitempty"`
	LastAttestationAttemptDate             *string                                      `json:"lastAttestationAttemptDate,omitempty"`
	LastSuccessfulAttestationDate          *string                                      `json:"lastSuccessfulAttestationDate,omitempty"`
	PasscodeLockGracePeriodEnforcedSeconds *int                                         `json:"passcodeLockGracePeriodEnforcedSeconds,omitempty"`
	PersonalDeviceProfileCurrent           *bool                                        `json:"personalDeviceProfileCurrent,omitempty"`
	LostModeEnabled                        *bool                                        `json:"lostModeEnabled,omitempty"`
	LostModePersistent                     *bool                                        `json:"lostModePersistent,omitempty"`
	LostModeMessage                        *string                                      `json:"lostModeMessage,omitempty"`
	LostModePhoneNumber                    *string                                      `json:"lostModePhoneNumber,omitempty"`
	LostModeFootnote                       *string                                      `json:"lostModeFootnote,omitempty"`
	LostModeLocation                       *MobileDeviceInventorySubsetSecurityLocation `json:"lostModeLocation,omitempty"`
	BootstraoTokenEscrowed                 *string                                      `json:"bootstrapTokenEscrowed,omitempty"`
}

type MobileDeviceInventorySubsetSecurityLocation struct {
	LastLocationUpdate                       *string `json:"lastLocationUpdate,omitempty"`
	LostModeLocationHorizontalAccuracyMeters *int    `json:"lostModeLocationHorizontalAccuracyMeters,omitempty"`
	LostModeLocationVerticalAccuracyMeters   *int    `json:"lostModeLocationVerticalAccuracyMeters,omitempty"`
	LostModeLocationAltitudeMeters           *int    `json:"lostModeLocationAltitudeMeters,omitempty"`
	LostModeLocationSpeedMetersPerSecond     *int    `json:"lostModeLocationSpeedMetersPerSecond,omitempty"`
	LostModeLocationCourseDegrees            *int    `json:"lostModeLocationCourseDegrees,omitempty"`
	LostModeLocationTimestamp                *string `json:"lostModeLocationTimestamp,omitempty"`
}

type MobileDeviceInventorySubsetEBook struct {
	Author          *string `json:"author,omitempty"`
	Title           *string `json:"title,omitempty"`
	Version         *string `json:"version,omitempty"`
	Kind            *string `json:"kind,omitempty"`
	ManagementState *string `json:"managementState,omitempty"`
}

type MobileDeviceInventorySubsetNetwork struct {
	CellularTechnology       *string `json:"cellularTechnology,omitempty"`
	VoiceRoamingEnabled      *bool   `json:"voiceRoamingEnabled,omitempty"`
	IMEI                     *string `json:"imei,omitempty"`
	ICCID                    *string `json:"iccid,omitempty"`
	MEID                     *string `json:"meid,omitempty"`
	EID                      *string `json:"eid,omitempty"`
	CarrierSettingsVersion   *string `json:"carrierSettingsVersion,omitempty"`
	CurrentCarrierNetwork    *string `json:"currentCarrierNetwork,omitempty"`
	CurrentMobileCountryCode *string `json:"currentMobileCountryCode,omitempty"`
	CurrentMobileNetworkCode *string `json:"currentMobileNetworkCode,omitempty"`
	HomeCarrierNetwork       *string `json:"homeCarrierNetwork,omitempty"`
	HomeMobileCountryCode    *string `json:"homeMobileCountryCode,omitempty"`
	HomeMobileNetworkCode    *string `json:"homeMobileNetworkCode,omitempty"`
	DataRoamingEnabled       *bool   `json:"dataRoamingEnabled,omitempty"`
	Roaming                  *bool   `json:"roaming,omitempty"`
	PersonalHotspotEnabled   *bool   `json:"personalHotspotEnabled,omitempty"`
	PhoneNumber              *string `json:"phoneNumber,omitempty"`
	PreferredVoiceNumber     *string `json:"preferredVoiceNumber,omitempty"`
}

type MobileDeviceInventorySubsetServiceSubscription struct {
	CarrierSettingsVersion   *string `json:"carrierSettingsVersion,omitempty"`
	CurrentCarrierNetwork    *string `json:"currentCarrierNetwork,omitempty"`
	CurrentMobileCountryCode *string `json:"currentMobileCountryCode,omitempty"`
	CurrentMobileNetworkCode *string `json:"currentMobileNetworkCode,omitempty"`
	SubscriberCarrierNetwork *string `json:"subscriberCarrierNetwork,omitempty"`
	EID                      *string `json:"eid,omitempty"`
	ICCID                    *string `json:"iccid,omitempty"`
	IMEI                     *string `json:"imei,omitempty"`
	DataPreferred            *bool   `json:"dataPreferred,omitempty"`
	Roaming                  *bool   `json:"roaming,omitempty"`
	VoicePreferred           *bool   `json:"voicePreferred,omitempty"`
	Label                    *string `json:"label,omitempty"`
	LabelID                  *string `json:"labelId,omitempty"`
	MEID                     *string `json:"meid,omitempty"`
	PhoneNumber              *string `json:"phoneNumber,omitempty"`
	Slot                     *string `json:"slot,omitempty"`
}

type MobileDeviceInventorySubsetProvisioningProfile struct {
	DisplayName    *string `json:"displayName,omitempty"`
	UUID           *string `json:"uuid,omitempty"`
	ExpirationDate *string `json:"expirationDate,omitempty"`
}

type MobileDeviceInventorySubsetSharedUser struct {
	ManagedAppleID *string `json:"managedAppleId,omitempty"`
	LoggedIn       *bool   `json:"loggedIn,omitempty"`
	DataToSync     *bool   `json:"dataToSync,omitempty"`
}

type MobileDeviceInventorySubsetPurchashing struct {
	Purchased           *bool                                            `json:"purchased,omitempty"`
	Leased              *bool                                            `json:"leased,omitempty"`
	PONumber            *string                                          `json:"poNumber,omitempty"`
	Vendor              *string                                          `json:"vendor,omitempty"`
	AppleCareID         *string                                          `json:"appleCareId,omitempty"`
	PurchasePrice       *string                                          `json:"purchasePrice,omitempty"`
	PurchasingAccount   *string                                          `json:"purchasingAccount,omitempty"`
	PODate              *string                                          `json:"poDate,omitempty"`
	WarrantyExpiresDate *string                                          `json:"warrantyExpiresDate,omitempty"`
	LeaseExpiresData    *string                                          `json:"leaseExpiresDate,omitempty"`
	LifeExpectancy      *int                                             `json:"lifeExpectancy,omitempty"`
	PurchasingContact   *string                                          `json:"purchasingContact,omitempty"`
	ExtensionAttributes []*MobileDeviceInventorySubsetExtensionAttribute `json:"extensionAttributes,omitempty"`
}

type MobileDeviceInventorySubsetUserProfile struct {
	DisplayName   *string `json:"displayName,omitempty"`
	Version       *string `json:"version,omitempty"`
	UUID          *string `json:"uuid,omitempty"`
	Identifier    *string `json:"identifier,omitempty"`
	Removable     *bool   `json:"removable,omitempty"`
	LastInstalled *string `json:"lastInstalled,omitempty"`
	Username      *string `json:"username,omitempty"`
}

func (c *Client) GetMobileDevicesInventory(params url.Values) (*ResponseMobileDeviceInventoryList, error) {
	endpoint := fmt.Sprintf("%s/detail", uriMobileDevicesInventory)
	resp, err := c.DoPaginatedGet(endpoint, params)

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
		if *inventory.General.DisplayName == name {
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
