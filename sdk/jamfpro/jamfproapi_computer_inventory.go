// jamfproapi_computer_inventory_detail.go
// Jamf Pro Api - Computer Inventory
// api reference: https://developer.jamf.com/jamf-pro/reference/get_v1-computers-inventory
// Jamf Pro API requires the structs to support a JSON data structure.

/*
Shared Resources in this Endpoint:
- SharedResourceSiteProAPI
*/

package jamfpro

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/mitchellh/mapstructure"
)

const uriComputersInventory = "/api/v1/computers-inventory"

// List

// ResponseComputerInventoryList represents the top-level JSON response structure.
type ResponseComputerInventoryList struct {
	TotalCount int                         `json:"totalCount"`
	Results    []ResourceComputerInventory `json:"results"`
}

// Resource

// ResponseComputerInventory represents an individual computer from the inventory.
type ResourceComputerInventory struct {
	ID                    *string                                        `json:"id,omitempty"`
	UDID                  *string                                        `json:"udid,omitempty"`
	General               *ComputerInventorySubsetGeneral                `json:"general,omitempty"`
	DiskEncryption        *ComputerInventorySubsetDiskEncryption         `json:"diskEncryption,omitempty"`
	Purchasing            *ComputerInventorySubsetPurchasing             `json:"purchasing,omitempty"`
	Applications          []*ComputerInventorySubsetApplication          `json:"applications,omitempty"`
	Storage               *ComputerInventorySubsetStorage                `json:"storage,omitempty"`
	UserAndLocation       *ComputerInventorySubsetUserAndLocation        `json:"userAndLocation,omitempty"`
	ConfigurationProfiles []*ComputerInventorySubsetConfigurationProfile `json:"configurationProfiles,omitempty"`
	Printers              []*ComputerInventorySubsetPrinter              `json:"printers,omitempty"`
	Services              []*ComputerInventorySubsetService              `json:"services,omitempty"`
	Hardware              *ComputerInventorySubsetHardware               `json:"hardware,omitempty"`
	LocalUserAccounts     []*ComputerInventorySubsetLocalUserAccount     `json:"localUserAccounts,omitempty"`
	Certificates          []*ComputerInventorySubsetCertificate          `json:"certificates,omitempty"`
	Attachments           []*ComputerInventorySubsetAttachment           `json:"attachments,omitempty"`
	Plugins               []*ComputerInventorySubsetPlugin               `json:"plugins,omitempty"`
	PackageReceipts       *ComputerInventorySubsetPackageReceipts        `json:"packageReceipts,omitempty"`
	Fonts                 []*ComputerInventorySubsetFont                 `json:"fonts,omitempty"`
	Security              *ComputerInventorySubsetSecurity               `json:"security,omitempty"`
	OperatingSystem       *ComputerInventorySubsetOperatingSystem        `json:"operatingSystem,omitempty"`
	LicensedSoftware      []*ComputerInventorySubsetLicensedSoftware     `json:"licensedSoftware,omitempty"`
	Ibeacons              []*ComputerInventorySubsetIBeacon              `json:"ibeacons,omitempty"`
	SoftwareUpdates       []*ComputerInventorySubsetSoftwareUpdate       `json:"softwareUpdates,omitempty"`
	ExtensionAttributes   []*ComputerInventorySubsetExtensionAttribute   `json:"extensionAttributes,omitempty"`
	ContentCaching        *ComputerInventorySubsetContentCaching         `json:"contentCaching,omitempty"`
	GroupMemberships      []*ComputerInventorySubsetGroupMembership      `json:"groupMemberships,omitempty"`
}

// Subsets

// General

type ComputerInventorySubsetGeneral struct {
	Name                                     *string                                         `json:"name,omitempty"`
	LastIpAddress                            *string                                         `json:"lastIpAddress,omitempty"`
	LastReportedIp                           *string                                         `json:"lastReportedIp,omitempty"`
	LastReportedIpV4                         *string                                         `json:"lastReportedIpV4"`
	LastReportedIpV6                         *string                                         `json:"lastReportedIpV6"`
	JamfBinaryVersion                        *string                                         `json:"jamfBinaryVersion,omitempty"`
	Platform                                 *string                                         `json:"platform,omitempty"`
	Barcode1                                 *string                                         `json:"barcode1"`
	Barcode2                                 *string                                         `json:"barcode2"`
	AssetTag                                 *string                                         `json:"assetTag,omitempty"`
	RemoteManagement                         *ComputerInventorySubsetGeneralRemoteManagement `json:"remoteManagement,omitempty"`
	Supervised                               *bool                                           `json:"supervised,omitempty"`
	MdmCapable                               *ComputerInventorySubsetGeneralMdmCapable       `json:"mdmCapable,omitempty"`
	ReportDate                               *string                                         `json:"reportDate,omitempty"`
	LastContactTime                          *string                                         `json:"lastContactTime,omitempty"`
	LastCloudBackupDate                      *string                                         `json:"lastCloudBackupDate,omitempty"`
	LastEnrolledDate                         *string                                         `json:"lastEnrolledDate,omitempty"`
	MdmProfileExpiration                     *string                                         `json:"mdmProfileExpiration,omitempty"`
	InitialEntryDate                         *string                                         `json:"initialEntryDate,omitempty"`
	DistributionPoint                        *string                                         `json:"distributionPoint,omitempty"`
	EnrollmentMethod                         *ComputerInventorySubsetGeneralEnrollmentMethod `json:"enrollmentMethod,omitempty"`
	Site                                     *SharedResourceSiteProAPI                       `json:"site,omitempty"`
	ItunesStoreAccountActive                 *bool                                           `json:"itunesStoreAccountActive,omitempty"`
	EnrolledViaAutomatedDeviceEnrollment     *bool                                           `json:"enrolledViaAutomatedDeviceEnrollment,omitempty"`
	UserApprovedMdm                          *bool                                           `json:"userApprovedMdm,omitempty"`
	DeclarativeDeviceManagementEnabled       *bool                                           `json:"declarativeDeviceManagementEnabled,omitempty"`
	ExtensionAttributes                      []*ComputerInventorySubsetExtensionAttribute    `json:"extensionAttributes,omitempty"`
	ManagementId                             *string                                         `json:"managementId,omitempty"`
	LastLoggedInUsernameSelfService          *string                                         `json:"lastLoggedInUsernameSelfService,omitempty"`
	LastLoggedInUsernameSelfServiceTimestamp *string                                         `json:"lastLoggedInUsernameSelfServiceTimestamp,omitempty"`
	LastLoggedInUsernameBinary               *string                                         `json:"lastLoggedInUsernameBinary,omitempty"`
	LastLoggedInUsernameBinaryTimestamp      *string                                         `json:"lastLoggedInUsernameBinaryTimestamp,omitempty"`
}

type ComputerInventorySubsetGeneralRemoteManagement struct {
	Managed            *bool   `json:"managed,omitempty"`
	ManagementUsername *string `json:"managementUsername,omitempty"`
}

type ComputerInventorySubsetGeneralMdmCapable struct {
	Capable            *bool                                           `json:"capable,omitempty"`
	CapableUsers       []*string                                       `json:"capableUsers,omitempty"`
	UserManagementInfo []*ComputerInventorySubsetGeneralMdmCapableUser `json:"userManagementInfo,omitempty"`
}

type ComputerInventorySubsetGeneralMdmCapableUser struct {
	CapableUser  *string `json:"capableUser,omitempty"`
	ManagementID *string `json:"managementId,omitempty"`
}

type ComputerInventorySubsetGeneralEnrollmentMethod struct {
	ID         *string `json:"id,omitempty"`
	ObjectName *string `json:"objectName,omitempty"`
	ObjectType *string `json:"objectType,omitempty"`
}

// Disk Encryption

type ComputerInventorySubsetDiskEncryption struct {
	BootPartitionEncryptionDetails      *ComputerInventorySubsetBootPartitionEncryptionDetails `json:"bootPartitionEncryptionDetails,omitempty"`
	IndividualRecoveryKeyValidityStatus *string                                                `json:"individualRecoveryKeyValidityStatus,omitempty"`
	InstitutionalRecoveryKeyPresent     *bool                                                  `json:"institutionalRecoveryKeyPresent,omitempty"`
	DiskEncryptionConfigurationName     *string                                                `json:"diskEncryptionConfigurationName,omitempty"`
	FileVault2Enabled                   *bool                                                  `json:"fileVault2Enabled"`
	FileVault2EnabledUserNames          []*string                                              `json:"fileVault2EnabledUserNames"`
	FileVault2EligibilityMessage        *string                                                `json:"fileVault2EligibilityMessage"`
}

// Purchasing

type ComputerInventorySubsetPurchasing struct {
	Leased              *bool                                        `json:"leased,omitempty"`
	Purchased           *bool                                        `json:"purchased,omitempty"`
	PoNumber            *string                                      `json:"poNumber,omitempty"`
	PoDate              *string                                      `json:"poDate,omitempty"`
	Vendor              *string                                      `json:"vendor,omitempty"`
	WarrantyDate        *string                                      `json:"warrantyDate,omitempty"`
	AppleCareId         *string                                      `json:"appleCareId,omitempty"`
	LeaseDate           *string                                      `json:"leaseDate,omitempty"`
	PurchasePrice       *string                                      `json:"purchasePrice,omitempty"`
	LifeExpectancy      *int                                         `json:"lifeExpectancy,omitempty"`
	PurchasingAccount   *string                                      `json:"purchasingAccount,omitempty"`
	PurchasingContact   *string                                      `json:"purchasingContact,omitempty"`
	ExtensionAttributes []*ComputerInventorySubsetExtensionAttribute `json:"extensionAttributes,omitempty"`
}

// Applications

type ComputerInventorySubsetApplication struct {
	Name              *string `json:"name,omitempty"`
	Path              *string `json:"path,omitempty"`
	Version           *string `json:"version,omitempty"`
	MacAppStore       *bool   `json:"macAppStore,omitempty"`
	SizeMegabytes     *int    `json:"sizeMegabytes,omitempty"`
	BundleId          *string `json:"bundleId,omitempty"`
	UpdateAvailable   *bool   `json:"updateAvailable,omitempty"`
	ExternalVersionId *string `json:"externalVersionId,omitempty"`
}

// Storage

type ComputerInventorySubsetStorage struct {
	BootDriveAvailableSpaceMegabytes *int                                  `json:"bootDriveAvailableSpaceMegabytes,omitempty"`
	Disks                            []*ComputerInventorySubsetStorageDisk `json:"disks,omitempty"`
}

type ComputerInventorySubsetStorageDisk struct {
	ID            *string                                        `json:"id,omitempty"`
	Device        *string                                        `json:"device,omitempty"`
	Model         *string                                        `json:"model,omitempty"`
	Revision      *string                                        `json:"revision,omitempty"`
	SerialNumber  *string                                        `json:"serialNumber,omitempty"`
	SizeMegabytes *int                                           `json:"sizeMegabytes,omitempty"`
	SmartStatus   *string                                        `json:"smartStatus,omitempty"`
	Type          *string                                        `json:"type,omitempty"`
	Partitions    []*ComputerInventorySubsetStorageDiskPartition `json:"partitions,omitempty"`
}

type ComputerInventorySubsetStorageDiskPartition struct {
	Name                      *string `json:"name,omitempty"`
	SizeMegabytes             *int    `json:"sizeMegabytes,omitempty"`
	AvailableMegabytes        *int    `json:"availableMegabytes,omitempty"`
	PartitionType             *string `json:"partitionType,omitempty"`
	PercentUsed               *int    `json:"percentUsed,omitempty"`
	FileVault2State           *string `json:"fileVault2State"`
	FileVault2ProgressPercent *int    `json:"fileVault2ProgressPercent"`
	LvmManaged                *bool   `json:"lvmManaged,omitempty"`
}

// User and Location

type ComputerInventorySubsetUserAndLocation struct {
	Username            *string                                      `json:"username,omitempty"`
	Realname            *string                                      `json:"realname,omitempty"`
	Email               *string                                      `json:"email,omitempty"`
	Position            *string                                      `json:"position,omitempty"`
	Phone               *string                                      `json:"phone,omitempty"`
	DepartmentId        *string                                      `json:"departmentId,omitempty"`
	BuildingId          *string                                      `json:"buildingId,omitempty"`
	Room                *string                                      `json:"room,omitempty"`
	ExtensionAttributes []*ComputerInventorySubsetExtensionAttribute `json:"extensionAttributes,omitempty"`
}

// Configuration Profiles

type ComputerInventorySubsetConfigurationProfile struct {
	ID                *string `json:"id,omitempty"`
	Username          *string `json:"username,omitempty"`
	LastInstalled     *string `json:"lastInstalled,omitempty"`
	Removable         *bool   `json:"removable,omitempty"`
	DisplayName       *string `json:"displayName,omitempty"`
	ProfileIdentifier *string `json:"profileIdentifier,omitempty"`
}

// Printers

type ComputerInventorySubsetPrinter struct {
	Name     *string `json:"name,omitempty"`
	Type     *string `json:"type,omitempty"`
	URI      *string `json:"uri,omitempty"`
	Location *string `json:"location,omitempty"`
}

// Services

type ComputerInventorySubsetService struct {
	Name *string `json:"name,omitempty"`
}

// Hardware

type ComputerInventorySubsetHardware struct {
	Make                   *string                                      `json:"make,omitempty"`
	Model                  *string                                      `json:"model,omitempty"`
	ModelIdentifier        *string                                      `json:"modelIdentifier,omitempty"`
	SerialNumber           *string                                      `json:"serialNumber,omitempty"`
	ProcessorSpeedMhz      *int                                         `json:"processorSpeedMhz,omitempty"`
	ProcessorCount         *int                                         `json:"processorCount,omitempty"`
	CoreCount              *int                                         `json:"coreCount,omitempty"`
	ProcessorType          *string                                      `json:"processorType,omitempty"`
	ProcessorArchitecture  *string                                      `json:"processorArchitecture,omitempty"`
	BusSpeedMhz            *int                                         `json:"busSpeedMhz,omitempty"`
	CacheSizeKilobytes     *int                                         `json:"cacheSizeKilobytes,omitempty"`
	NetworkAdapterType     *string                                      `json:"networkAdapterType,omitempty"`
	MacAddress             *string                                      `json:"macAddress,omitempty"`
	AltNetworkAdapterType  *string                                      `json:"altNetworkAdapterType,omitempty"`
	AltMacAddress          *string                                      `json:"altMacAddress,omitempty"`
	TotalRamMegabytes      *int                                         `json:"totalRamMegabytes,omitempty"`
	OpenRamSlots           *int                                         `json:"openRamSlots,omitempty"`
	BatteryCapacityPercent *int                                         `json:"batteryCapacityPercent,omitempty"`
	BatteryHealth          *string                                      `json:"batteryHealth,omitempty"`
	SmcVersion             *string                                      `json:"smcVersion,omitempty"`
	NicSpeed               *string                                      `json:"nicSpeed,omitempty"`
	OpticalDrive           *string                                      `json:"opticalDrive,omitempty"`
	BootRom                *string                                      `json:"bootRom,omitempty"`
	BleCapable             *bool                                        `json:"bleCapable,omitempty"`
	SupportsIosAppInstalls *bool                                        `json:"supportsIosAppInstalls,omitempty"`
	AppleSilicon           *bool                                        `json:"appleSilicon,omitempty"`
	ProvisioningUdid       *string                                      `json:"provisioningUdid,omitempty"`
	ExtensionAttributes    []*ComputerInventorySubsetExtensionAttribute `json:"extensionAttributes,omitempty"`
}

// Local User Accounts

type ComputerInventorySubsetLocalUserAccount struct {
	UID                            *string `json:"uid,omitempty"`
	UserGuid                       *string `json:"userGuid,omitempty"`
	Username                       *string `json:"username,omitempty"`
	FullName                       *string `json:"fullName,omitempty"`
	Admin                          *bool   `json:"admin,omitempty"`
	HomeDirectory                  *string `json:"homeDirectory,omitempty"`
	HomeDirectorySizeMb            *int    `json:"homeDirectorySizeMb,omitempty"`
	FileVault2Enabled              *bool   `json:"fileVault2Enabled"`
	UserAccountType                *string `json:"userAccountType,omitempty"`
	PasswordMinLength              *int    `json:"passwordMinLength,omitempty"`
	PasswordMaxAge                 *int    `json:"passwordMaxAge,omitempty"`
	PasswordMinComplexCharacters   *int    `json:"passwordMinComplexCharacters,omitempty"`
	PasswordHistoryDepth           *int    `json:"passwordHistoryDepth,omitempty"`
	PasswordRequireAlphanumeric    *bool   `json:"passwordRequireAlphanumeric,omitempty"`
	ComputerAzureActiveDirectoryId *string `json:"computerAzureActiveDirectoryId,omitempty"`
	UserAzureActiveDirectoryId     *string `json:"userAzureActiveDirectoryId,omitempty"`
	AzureActiveDirectoryId         *string `json:"azureActiveDirectoryId,omitempty"`
}

// Certificates

type ComputerInventorySubsetCertificate struct {
	CommonName        *string `json:"commonName,omitempty"`
	Identity          *bool   `json:"identity,omitempty"`
	ExpirationDate    *string `json:"expirationDate,omitempty"`
	Username          *string `json:"username,omitempty"`
	LifecycleStatus   *string `json:"lifecycleStatus,omitempty"`
	CertificateStatus *string `json:"certificateStatus,omitempty"`
	SubjectName       *string `json:"subjectName,omitempty"`
	SerialNumber      *string `json:"serialNumber,omitempty"`
	Sha1Fingerprint   *string `json:"sha1Fingerprint"`
	IssuedDate        *string `json:"issuedDate,omitempty"`
}

// Attachments

type ComputerInventorySubsetAttachment struct {
	ID        *string `json:"id,omitempty"`
	Name      *string `json:"name,omitempty"`
	FileType  *string `json:"fileType,omitempty"`
	SizeBytes *int    `json:"sizeBytes,omitempty"`
}

// Plugins

type ComputerInventorySubsetPlugin struct {
	Name    *string `json:"name,omitempty"`
	Version *string `json:"version,omitempty"`
	Path    *string `json:"path,omitempty"`
}

// Package Receipts

type ComputerInventorySubsetPackageReceipts struct {
	InstalledByJamfPro      []*string `json:"installedByJamfPro,omitempty"`
	InstalledByInstallerSwu []*string `json:"installedByInstallerSwu,omitempty"`
	Cached                  []*string `json:"cached,omitempty"`
}

// Fonts

type ComputerInventorySubsetFont struct {
	Name    *string `json:"name,omitempty"`
	Version *string `json:"version,omitempty"`
	Path    *string `json:"path,omitempty"`
}

// Security

type ComputerInventorySubsetSecurity struct {
	SipStatus                    *string `json:"sipStatus,omitempty"`
	GatekeeperStatus             *string `json:"gatekeeperStatus,omitempty"`
	XprotectVersion              *string `json:"xprotectVersion,omitempty"`
	AutoLoginDisabled            *bool   `json:"autoLoginDisabled,omitempty"`
	RemoteDesktopEnabled         *bool   `json:"remoteDesktopEnabled,omitempty"`
	ActivationLockEnabled        *bool   `json:"activationLockEnabled,omitempty"`
	RecoveryLockEnabled          *bool   `json:"recoveryLockEnabled,omitempty"`
	FirewallEnabled              *bool   `json:"firewallEnabled,omitempty"`
	SecureBootLevel              *string `json:"secureBootLevel,omitempty"`
	ExternalBootLevel            *string `json:"externalBootLevel,omitempty"`
	BootstrapTokenAllowed        *bool   `json:"bootstrapTokenAllowed,omitempty"`
	BootstrapTokenEscrowedStatus *string `json:"bootstrapTokenEscrowedStatus,omitempty"`
	LastAttestationAttempt       *string `json:"lastAttestationAttempt,omitempty"`
	LastSuccessfulAttestation    *string `json:"lastSuccessfulAttestation,omitempty"`
	AttestationStatus            *string `json:"attestationStatus,omitempty"`
}

// Operating System

type ComputerInventorySubsetOperatingSystem struct {
	Name                     *string                                      `json:"name,omitempty"`
	Version                  *string                                      `json:"version,omitempty"`
	Build                    *string                                      `json:"build,omitempty"`
	SupplementalBuildVersion *string                                      `json:"supplementalBuildVersion,omitempty"`
	RapidSecurityResponse    *string                                      `json:"rapidSecurityResponse,omitempty"`
	ActiveDirectoryStatus    *string                                      `json:"activeDirectoryStatus,omitempty"`
	FileVault2Status         *string                                      `json:"fileVault2Status"`
	SoftwareUpdateDeviceId   *string                                      `json:"softwareUpdateDeviceId,omitempty"`
	ExtensionAttributes      []*ComputerInventorySubsetExtensionAttribute `json:"extensionAttributes,omitempty"`
}

// Licensed Software

type ComputerInventorySubsetLicensedSoftware struct {
	ID   *string `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
}

// IBeacon

type ComputerInventorySubsetIBeacon struct {
	Name *string `json:"name,omitempty"`
}

// Software Updates

type ComputerInventorySubsetSoftwareUpdate struct {
	Name        *string `json:"name,omitempty"`
	Version     *string `json:"version,omitempty"`
	PackageName *string `json:"packageName,omitempty"`
}

// Content Caching

type ComputerInventorySubsetContentCaching struct {
	ComputerContentCachingInformationId *string                                                  `json:"computerContentCachingInformationId,omitempty"`
	Parents                             []*ComputerInventorySubsetContentCachingParent           `json:"parents,omitempty"`
	Alerts                              []*ComputerInventorySubsetContentCachingAlert            `json:"alerts,omitempty"` // Corrected to slice
	Activated                           *bool                                                    `json:"activated,omitempty"`
	Active                              *bool                                                    `json:"active,omitempty"`
	ActualCacheBytesUsed                *int                                                     `json:"actualCacheBytesUsed,omitempty"`
	CacheDetails                        []*ComputerInventorySubsetContentCachingCacheDetail      `json:"cacheDetails,omitempty"`
	CacheBytesFree                      *int                                                     `json:"cacheBytesFree,omitempty"`
	CacheBytesLimit                     *int                                                     `json:"cacheBytesLimit,omitempty"`
	CacheStatus                         *string                                                  `json:"cacheStatus,omitempty"`
	CacheBytesUsed                      *int                                                     `json:"cacheBytesUsed,omitempty"`
	DataMigrationCompleted              *bool                                                    `json:"dataMigrationCompleted,omitempty"`
	DataMigrationProgressPercentage     *int                                                     `json:"dataMigrationProgressPercentage,omitempty"`
	DataMigrationError                  *ComputerInventorySubsetContentCachingDataMigrationError `json:"dataMigrationError,omitempty"`
	MaxCachePressureLast1HourPercentage *int                                                     `json:"maxCachePressureLast1HourPercentage"`
	PersonalCacheBytesFree              *int                                                     `json:"personalCacheBytesFree,omitempty"`
	PersonalCacheBytesLimit             *int                                                     `json:"personalCacheBytesLimit,omitempty"`
	PersonalCacheBytesUsed              *int                                                     `json:"personalCacheBytesUsed,omitempty"`
	Port                                *int                                                     `json:"port,omitempty"`
	PublicAddress                       *string                                                  `json:"publicAddress,omitempty"`
	RegistrationError                   *string                                                  `json:"registrationError,omitempty"`
	RegistrationResponseCode            *int                                                     `json:"registrationResponseCode,omitempty"`
	RegistrationStarted                 *string                                                  `json:"registrationStarted,omitempty"`
	RegistrationStatus                  *string                                                  `json:"registrationStatus,omitempty"`
	RestrictedMedia                     *bool                                                    `json:"restrictedMedia,omitempty"`
	ServerGuid                          *string                                                  `json:"serverGuid,omitempty"`
	StartupStatus                       *string                                                  `json:"startupStatus,omitempty"`
	TetheratorStatus                    *string                                                  `json:"tetheratorStatus,omitempty"`
	TotalBytesAreSince                  *string                                                  `json:"totalBytesAreSince,omitempty"`
	TotalBytesDropped                   *int64                                                   `json:"totalBytesDropped,omitempty"`
	TotalBytesImported                  *int64                                                   `json:"totalBytesImported,omitempty"`
	TotalBytesReturnedToChildren        *int64                                                   `json:"totalBytesReturnedToChildren,omitempty"`
	TotalBytesReturnedToClients         *int64                                                   `json:"totalBytesReturnedToClients,omitempty"`
	TotalBytesReturnedToPeers           *int64                                                   `json:"totalBytesReturnedToPeers,omitempty"`
	TotalBytesStoredFromOrigin          *int64                                                   `json:"totalBytesStoredFromOrigin,omitempty"`
	TotalBytesStoredFromParents         *int64                                                   `json:"totalBytesStoredFromParents,omitempty"`
	TotalBytesStoredFromPeers           *int64                                                   `json:"totalBytesStoredFromPeers,omitempty"`
}

type ComputerInventorySubsetContentCachingParent struct {
	ContentCachingParentId *string                                             `json:"contentCachingParentId,omitempty"`
	Address                *string                                             `json:"address,omitempty"`
	Alerts                 *ComputerInventorySubsetContentCachingAlert         `json:"alerts,omitempty"` // Changed from slice to struct
	Details                *ComputerInventorySubsetContentCachingParentDetails `json:"details,omitempty"`
	Guid                   *string                                             `json:"guid,omitempty"`
	Healthy                *bool                                               `json:"healthy,omitempty"`
	Port                   *int                                                `json:"port,omitempty"`
	Version                *string                                             `json:"version,omitempty"`
}

type ComputerInventorySubsetContentCachingParentDetails struct {
	ContentCachingParentDetailsId *string                                                           `json:"contentCachingParentDetailsId,omitempty"`
	AcPower                       *bool                                                             `json:"acPower,omitempty"`
	CacheSizeBytes                *int64                                                            `json:"cacheSizeBytes,omitempty"`
	Capabilities                  *ComputerInventorySubsetContentCachingParentDetailsCapabilities   `json:"capabilities,omitempty"`
	Portable                      *bool                                                             `json:"portable,omitempty"`
	LocalNetwork                  []*ComputerInventorySubsetContentCachingParentDetailsLocalNetwork `json:"localNetwork,omitempty"`
}

type ComputerInventorySubsetContentCachingParentDetailsCapabilities struct {
	ContentCachingParentCapabilitiesId *string `json:"contentCachingParentCapabilitiesId,omitempty"`
	Imports                            *bool   `json:"imports,omitempty"`
	Namespaces                         *bool   `json:"namespaces,omitempty"`
	PersonalContent                    *bool   `json:"personalContent,omitempty"`
	QueryParameters                    *bool   `json:"queryParameters,omitempty"`
	SharedContent                      *bool   `json:"sharedContent,omitempty"`
	Prioritization                     *bool   `json:"prioritization,omitempty"`
}

type ComputerInventorySubsetContentCachingParentDetailsLocalNetwork struct {
	ContentCachingParentLocalNetworkId *string `json:"contentCachingParentLocalNetworkId,omitempty"`
	Speed                              *int    `json:"speed,omitempty"`
	Wired                              *bool   `json:"wired,omitempty"`
}

type ComputerInventorySubsetContentCachingCacheDetail struct {
	ComputerContentCachingCacheDetailsId *string `json:"computerContentCachingCacheDetailsId,omitempty"`
	CategoryName                         *string `json:"categoryName,omitempty"`
	DiskSpaceBytesUsed                   *int64  `json:"diskSpaceBytesUsed,omitempty"`
}

type ComputerInventorySubsetContentCachingDataMigrationError struct {
	Code     *int                                                               `json:"code,omitempty"`
	Domain   *string                                                            `json:"domain,omitempty"`
	UserInfo []*ComputerInventorySubsetContentCachingDataMigrationErrorUserInfo `json:"userInfo,omitempty"`
}

type ComputerInventorySubsetContentCachingDataMigrationErrorUserInfo struct {
	Key   *string `json:"key,omitempty"`
	Value *string `json:"value,omitempty"`
}

// Group Memberships

type ComputerInventorySubsetGroupMembership struct {
	GroupId          *string `json:"groupId,omitempty"`
	GroupName        *string `json:"groupName,omitempty"`
	GroupDescription *string `json:"groupDescription,omitempty"`
	SmartGroup       *bool   `json:"smartGroup,omitempty"`
}

// Shared

// ExtensionAttribute represents a generic extension attribute.
type ComputerInventorySubsetExtensionAttribute struct {
	DefinitionId *string   `json:"definitionId,omitempty"`
	Name         *string   `json:"name,omitempty"`
	Description  *string   `json:"description,omitempty"`
	Enabled      *bool     `json:"enabled,omitempty"`
	MultiValue   *bool     `json:"multiValue,omitempty"`
	Values       []*string `json:"values,omitempty"`
	DataType     *string   `json:"dataType,omitempty"`
	Options      []*string `json:"options,omitempty"`
	InputType    *string   `json:"inputType,omitempty"`
}

// BootPartitionEncryptionDetails represents the details of disk encryption.
type ComputerInventorySubsetBootPartitionEncryptionDetails struct {
	PartitionName              *string `json:"partitionName,omitempty"`
	PartitionFileVault2State   *string `json:"partitionFileVault2State"`
	PartitionFileVault2Percent *int    `json:"partitionFileVault2Percent"`
}

// ContentCachingAlert represents an alert in the content caching details.
type ComputerInventorySubsetContentCachingAlert struct {
	ContentCachingParentAlertId *string   `json:"contentCachingParentAlertId,omitempty"`
	Addresses                   []*string `json:"addresses,omitempty"`
	ClassName                   *string   `json:"className,omitempty"`
	PostDate                    *string   `json:"postDate,omitempty"`
	CacheBytesLimit             *int      `json:"cacheBytesLimit,omitempty"`
	PathPreventingAccess        *string   `json:"pathPreventingAccess,omitempty"`
	ReservedVolumeBytes         *int      `json:"reservedVolumeBytes,omitempty"`
	Resource                    *string   `json:"resource,omitempty"`
}

// FileVaultInventoryList represents the paginated FileVault inventory response.
type FileVaultInventoryList struct {
	TotalCount int                  `json:"totalCount"`
	Results    []FileVaultInventory `json:"results"`
}

// FileVaultInventory represents the FileVault information for a single computer.
type FileVaultInventory struct {
	ComputerId                          *string                                                `json:"computerId,omitempty"`
	Name                                *string                                                `json:"name,omitempty"`
	PersonalRecoveryKey                 *string                                                `json:"personalRecoveryKey,omitempty"`
	BootPartitionEncryptionDetails      *ComputerInventorySubsetBootPartitionEncryptionDetails `json:"bootPartitionEncryptionDetails,omitempty"`
	IndividualRecoveryKeyValidityStatus *string                                                `json:"individualRecoveryKeyValidityStatus,omitempty"`
	InstitutionalRecoveryKeyPresent     *bool                                                  `json:"institutionalRecoveryKeyPresent,omitempty"`
	DiskEncryptionConfigurationName     *string                                                `json:"diskEncryptionConfigurationName,omitempty"`
}

// ResponseRecoveryLockPassword represents the response structure for a recovery lock password.
type ResponseRecoveryLockPassword struct {
	RecoveryLockPassword string `json:"recoveryLockPassword,omitempty"`
}

// ResponseUploadAttachment represents the response structure for uploading an attachment.
type ResponseUploadAttachment struct {
	ID   string `json:"id,omitempty"`
	Href string `json:"href,omitempty"`
}

// ResponseRemoveMDMProfile represents the response structure for removing an MDM profile.
type ResponseRemoveMDMProfile struct {
	DeviceID    string `json:"deviceId,omitempty"`
	CommandUUID string `json:"commandUuid,omitempty"`
}

// Request

// RequestEraseDeviceComputer represents the request structure for erasing a device.
type RequestEraseDeviceComputer struct {
	Pin *string `json:"pin,omitempty"`
}

// CRUD

// GetComputersInventory retrieves all computer inventory information with optional sorting and section filters.
func (c *Client) GetComputersInventory(params url.Values) (*ResponseComputerInventoryList, error) {
	resp, err := c.DoPaginatedGet(uriComputersInventory, params)

	if err != nil {
		return nil, fmt.Errorf(errMsgFailedPaginatedGet, "computers-inventories", err)
	}

	var out ResponseComputerInventoryList
	out.TotalCount = resp.Size

	for _, value := range resp.Results {
		var newObj ResourceComputerInventory
		err := mapstructure.Decode(value, &newObj)
		if err != nil {
			return nil, fmt.Errorf(errMsgFailedMapstruct, "computer-inventory", err)
		}
		out.Results = append(out.Results, newObj)
	}

	return &out, nil
}

// GetComputerInventoryByID retrieves a specific computer's inventory information by its ID.
func (c *Client) GetComputerInventoryByID(id string) (*ResourceComputerInventory, error) {
	endpoint := fmt.Sprintf("%s/%s", uriComputersInventory, id)

	// Fetch the computer inventory by ID
	var responseInventory ResourceComputerInventory
	resp, err := c.HTTP.DoRequest("GET", endpoint, nil, &responseInventory)
	if err != nil {
		return nil, fmt.Errorf(errMsgFailedGetByID, "computer inventory", id, err)
	}

	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	return &responseInventory, nil
}

// GetComputerInventoryByName retrieves a specific computer's inventory information by its name.
func (c *Client) GetComputerInventoryByName(name string) (*ResourceComputerInventory, error) {
	inventories, err := c.GetComputersInventory(nil)
	if err != nil {
		return nil, fmt.Errorf(errMsgFailedPaginatedGet, "computer inventory", err)
	}

	for _, inventory := range inventories.Results {
		if *inventory.General.Name == name {
			return &inventory, nil
		}
	}

	return nil, fmt.Errorf(errMsgFailedGetByName, "computer inventory", name, err)
}

// UpdateComputerInventoryByID updates a specific computer's inventory information by its ID.
func (c *Client) UpdateComputerInventoryByID(id string, inventoryUpdate *ResourceComputerInventory) (*ResourceComputerInventory, error) {
	endpoint := fmt.Sprintf("%s-detail/%s", uriComputersInventory, id)

	var updatedInventory ResourceComputerInventory
	resp, err := c.HTTP.DoRequest("PATCH", endpoint, inventoryUpdate, &updatedInventory)
	if err != nil {
		return nil, fmt.Errorf(errMsgFailedUpdateByID, "computer inventory", id, err)
	}

	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	return &updatedInventory, nil
}

// DeleteComputerInventoryByID deletes a computer's inventory information by its ID.
func (c *Client) DeleteComputerInventoryByID(id string) error {
	endpoint := fmt.Sprintf("%s/%s", uriComputersInventory, id)

	resp, err := c.HTTP.DoRequest("DELETE", endpoint, nil, nil)
	if err != nil {
		return fmt.Errorf(errMsgFailedDeleteByID, "computer-iventory", id, err)
	}

	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}

// GetComputersFileVaultInventory retrieves all computer inventory filevault information.
func (c *Client) GetComputersFileVaultInventory(params url.Values) (*FileVaultInventoryList, error) {
	endpoint := fmt.Sprintf("%s/filevault", uriComputersInventory)
	resp, err := c.DoPaginatedGet(endpoint, params)

	if err != nil {
		return nil, fmt.Errorf(errMsgFailedPaginatedGet, "filevault inventories", err)
	}

	var out FileVaultInventoryList
	out.TotalCount = resp.Size
	for _, value := range resp.Results {
		var newObj FileVaultInventory
		err := mapstructure.Decode(value, &newObj)
		if err != nil {
			return nil, fmt.Errorf(errMsgFailedMapstruct, "filevault inventory", err)
		}
		out.Results = append(out.Results, newObj)
	}

	return &out, nil
}

// GetComputerFileVaultInventoryByID returns file vault details by the computer ID.
func (c *Client) GetComputerFileVaultInventoryByID(id string) (*FileVaultInventory, error) {
	endpoint := fmt.Sprintf("%s/%s/filevault", uriComputersInventory, id)

	var fileVaultInventory FileVaultInventory
	resp, err := c.HTTP.DoRequest("GET", endpoint, nil, &fileVaultInventory)
	if err != nil {
		return nil, fmt.Errorf(errMsgFailedGetByID, "file value inventory", id, err)
	}

	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	return &fileVaultInventory, nil
}

// GetComputerRecoveryLockPasswordByID returns a computer recover lock password by the computer ID.
func (c *Client) GetComputerRecoveryLockPasswordByID(id string) (*ResponseRecoveryLockPassword, error) {
	endpoint := fmt.Sprintf("%s/%s/view-recovery-lock-password", uriComputersInventory, id)

	var recoveryLockPasswordResponse ResponseRecoveryLockPassword
	resp, err := c.HTTP.DoRequest("GET", endpoint, nil, &recoveryLockPasswordResponse)
	if err != nil {
		return nil, fmt.Errorf(errMsgFailedGetByID, "recovery lock password", id, err)
	}

	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	return &recoveryLockPasswordResponse, nil
}

// TODO

// UploadAttachmentAndAssignToComputerByID uploads a file attachment to a computer by computer ID.
// Api supports single file upload only.
func (c *Client) UploadAttachmentAndAssignToComputerByID(id string, filePaths []string) (*ResponseUploadAttachment, error) {
	// Validate input
	if len(filePaths) == 0 {
		return nil, fmt.Errorf("no file paths provided")
	}
	if len(filePaths) > 1 {
		return nil, fmt.Errorf("API only supports single file upload, %d files provided", len(filePaths))
	}

	endpoint := fmt.Sprintf("%s/%s/attachments", uriComputersInventory, id)

	files := map[string][]string{
		"file": filePaths,
	}

	// Include form fields if needed (currently none required by API)
	formFields := map[string]string{}

	// No custom content types needed, will default to application/octet-stream
	contentTypes := map[string]string{}

	// No additional headers needed for this request
	headersMap := map[string]http.Header{}

	var response ResponseUploadAttachment
	resp, err := c.HTTP.DoMultiPartRequest(
		http.MethodPost,
		endpoint,
		files,
		formFields,
		contentTypes,
		headersMap,
		"byte",
		&response,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to upload attachment: %v", err)
	}
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	return &response, nil
}

// DeleteAttachmentByIDAndComputerID deletes a computer's inventory attached by computer ID
// and the computer's attachment ID. Multiple attachments can be assigned to a single computer resource.
func (c *Client) DeleteAttachmentByIDAndComputerID(computerID, attachmentID string) error {
	endpoint := fmt.Sprintf("%s/%s/attachments/%s", uriComputersInventory, computerID, attachmentID)

	resp, err := c.HTTP.DoRequest("DELETE", endpoint, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to delete attachment: %v", err)
	}

	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("failed to delete attachment, status code: %d", resp.StatusCode)
	}

	return nil
}

// RemoveComputerMDMProfile removes the MDM profile from a computer by its ID.
func (c *Client) RemoveComputerMDMProfile(id string) (*ResponseRemoveMDMProfile, error) {
	endpoint := fmt.Sprintf("%s/%s/remove-mdm-profile", uriComputersInventory, id)

	var response ResponseRemoveMDMProfile
	resp, err := c.HTTP.DoRequest("POST", endpoint, nil, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to remove MDM profile for computer ID %s: %v", id, err)
	}

	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	return &response, nil
}

// EraseComputerByID erases a computer by its ID.
func (c *Client) EraseComputerByID(id string, devicePin RequestEraseDeviceComputer) error {
	endpoint := fmt.Sprintf("%s/%s/erase", uriComputersInventory, id)

	resp, err := c.HTTP.DoRequest("POST", endpoint, devicePin, nil)
	if err != nil {
		return fmt.Errorf(errMsgFailedActionByID, "erase computer", id, err)
	}

	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}
