// +build linux

package ste

import (
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-storage-azcopy/v10/common"
	"github.com/Azure/azure-storage-azcopy/v10/sddl"
	"github.com/Azure/azure-storage-file-go/azfile"
)

// This file os-triggers the ISMBPropertyBearingSourceInfoProvider interface on a local SIP.
// Note: Linux SIP doesn't implement the ICustomLocalOpener since it doesn't need to do anything special, unlike
//       Windows where we need to pass FILE_FLAG_BACKUP_SEMANTICS flag for opening file.

func (f localFileSourceInfoProvider) GetSDDL() (string, error) {
	// We only need Owner, Group, and DACLs for azure files, CIFS_XATTR_CIFS_NTSD gets us that.
	const securityInfoFlags sddl.SECURITY_INFORMATION = sddl.DACL_SECURITY_INFORMATION | sddl.OWNER_SECURITY_INFORMATION | sddl.GROUP_SECURITY_INFORMATION

	// Query the Security Descriptor object for the given file.
	sd, err := sddl.QuerySecurityObject(f.jptm.Info().Source, securityInfoFlags)
	if err != nil {
		return "", fmt.Errorf("sddl.QuerySecurityObject(%s, 0x%x) failed: %w",
			f.jptm.Info().Source, securityInfoFlags, err)
	}

	// Convert the binary Security Descriptor to string in SDDL format.
	// This is the Windows equivalent of ConvertSecurityDescriptorToStringSecurityDescriptorW().
	sdStr, err := sddl.SecurityDescriptorToString(sd)
	if err != nil {
		// Panic, as it's unexpected and we would want to know.
		panic("Cannot parse binary Security Descriptor returned by QuerySecurityObject")
	}

	fSDDL, err := sddl.ParseSDDL(sdStr)
	if err != nil {
		return "", fmt.Errorf("sddl.ParseSDDL(%s) failed: %w", sdStr, err)
	}

	if strings.TrimSpace(fSDDL.String()) != strings.TrimSpace(sdStr) {
		panic("SDDL sanity check failed (parsed string output != original string)")
	}

	return fSDDL.PortableString(), nil
}

func (f localFileSourceInfoProvider) GetSMBProperties() (TypedSMBPropertyHolder, error) {
	info, err := common.GetFileInformation(f.jptm.Info().Source)

	return HandleInfo{info}, err
}

type HandleInfo struct {
	common.ByHandleFileInformation
}

func (hi HandleInfo) FileCreationTime() time.Time {
	// This returns nanoseconds since Unix Epoch.
	return time.Unix(0, hi.CreationTime.Nanoseconds())
}

func (hi HandleInfo) FileLastWriteTime() time.Time {
	// This returns nanoseconds since Unix Epoch.
	return time.Unix(0, hi.LastWriteTime.Nanoseconds())
}

func (hi HandleInfo) FileAttributes() azfile.FileAttributeFlags {
	// Can't shorthand it because the function name overrides.
	return azfile.FileAttributeFlags(hi.ByHandleFileInformation.FileAttributes)
}
