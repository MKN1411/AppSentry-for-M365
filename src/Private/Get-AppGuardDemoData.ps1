function Get-AppGuardDemoData {
    <#
    .SYNOPSIS
        Generates realistic Microsoft 365 / Entra ID tenant policy and application inventory data for local testing, demos, and Pester tests.
    .DESCRIPTION
        Includes all 10 global tenant app protection settings (with realistic misconfigurations like allowed password additions on apps/service principals)
        and a representative mix of Enterprise Applications and App Registrations (including the ConnectWise Cloud Backup IOC, a privilege escalation app,
        an unverified shadow IT app, and well-hardened green apps).
    #>
    [CmdletBinding()]
    param()

    $Now = [DateTime]::UtcNow

    $TenantPoliciesRaw = [PSCustomObject]@{
        TenantId   = '72f988bf-86f1-41af-91ab-2d7cd011db47'
        TenantName = 'Contoso Enterprise Europe GmbH (Demo Tenant)'
        AuthorizationPolicy = [PSCustomObject]@{
            id                          = 'authorizationPolicy'
            allowInvitesFrom            = 'everyone'
            allowUserConsentForRiskyApps = $true
            defaultUserRolePermissions  = [PSCustomObject]@{
                allowedToCreateApps         = $true
                allowedToCreateSecurityGroups = $true
                permissionGrantPoliciesAssigned = @(
                    'ManagePermissionGrantsForSelf.microsoft-user-default-legacy',
                    'ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team'
                )
            }
        }
        AdminConsentRequestPolicy = [PSCustomObject]@{
            isEnabled             = $false
            notifyReviewers       = $false
            remindersEnabled      = $false
            requestDurationInDays = 30
            reviewers             = @()
        }
        DefaultAppManagementPolicy = [PSCustomObject]@{
            id          = '00000000-0000-0000-0000-000000000000'
            displayName = 'Default app management tenant policy'
            isEnabled   = $false
            applicationRestrictions = [PSCustomObject]@{
                passwordCredentials = @(
                    [PSCustomObject]@{
                        restrictionType = 'passwordAddition'
                        state           = 'disabled'
                        maxLifetime     = $null
                    },
                    [PSCustomObject]@{
                        restrictionType = 'passwordLifetime'
                        state           = 'disabled'
                        maxLifetime     = 'P730D'
                    },
                    [PSCustomObject]@{
                        restrictionType = 'customPasswordAddition'
                        state           = 'disabled'
                    }
                )
                keyCredentials = @(
                    [PSCustomObject]@{
                        restrictionType = 'asymmetricKeyLifetime'
                        state           = 'disabled'
                        maxLifetime     = $null
                    }
                )
            }
            servicePrincipalRestrictions = [PSCustomObject]@{
                passwordCredentials = @(
                    [PSCustomObject]@{
                        restrictionType = 'passwordAddition'
                        state           = 'disabled'
                        maxLifetime     = $null
                    },
                    [PSCustomObject]@{
                        restrictionType = 'passwordLifetime'
                        state           = 'disabled'
                        maxLifetime     = $null
                    }
                )
                keyCredentials = @()
            }
        }
        CrossTenantDefaultPolicy = [PSCustomObject]@{
            isServiceDefault = $true
            b2bCollaborationOutbound = [PSCustomObject]@{
                applications = [PSCustomObject]@{ accessType = 'allowed' }
            }
            b2bCollaborationInbound = [PSCustomObject]@{
                applications = [PSCustomObject]@{ accessType = 'allowed' }
            }
        }
        DirectoryAudits = @(
            [PSCustomObject]@{
                id                = 'audit-demo-t13'
                category          = 'Policy'
                activityDisplayName = 'Update authorization policy'
                activityDateTime  = $Now.AddMinutes(-15).ToString('yyyy-MM-dd HH:mm:ss UTC')
                initiatedBy       = [PSCustomObject]@{
                    user = [PSCustomObject]@{
                        id                = 'a1b2c3d4-5566-4777-8899-001122334455'
                        userPrincipalName = 'secadmin@contoso.de'
                        displayName       = 'Security Admin'
                    }
                }
                targetResources   = @(
                    [PSCustomObject]@{
                        id          = 'authorizationPolicy'
                        displayName = 'Authorization Policy'
                        type        = 'Policy'
                        modifiedProperties = @(
                            [PSCustomObject]@{
                                displayName = 'GuestUserRoleId'
                                oldValue    = '"10dae51f-b6af-4016-8d66-8c2a99b929b3"'
                                newValue    = '"2af84b1e-32c8-42b7-82bc-daa82404023b"'
                            }
                        )
                    }
                )
            },
            [PSCustomObject]@{
                id                = 'audit-demo-app1'
                category          = 'ApplicationManagement'
                activityDisplayName = 'Update service principal'
                activityDateTime  = $Now.AddHours(-2).ToString('yyyy-MM-dd HH:mm:ss UTC')
                initiatedBy       = [PSCustomObject]@{
                    user = [PSCustomObject]@{
                        id                = 'a1b2c3d4-5566-4777-8899-001122334455'
                        userPrincipalName = 'secadmin@contoso.de'
                        displayName       = 'Security Admin'
                    }
                }
                targetResources   = @(
                    [PSCustomObject]@{
                        id          = 'sp-1005-cw-disabled-id'
                        displayName = 'ConnectWise Cloud Management (Base - Contained)'
                        type        = 'ServicePrincipal'
                    }
                )
            }
        )
    }

    $AppsRaw = @(
        # 1. CRITICAL RED: ConnectWise Cloud Backup (SkyKick) - Active IOC + Broad Access + Local Backdoor Secret
        [PSCustomObject]@{
            ObjectId                  = 'sp-1001-cw-backup-object-id'
            AppRegistrationObjectId   = $null
            AppId                     = '506e08f9-6e9a-4da4-942b-a099a03644ae'
            DisplayName               = 'ConnectWise Cloud Backup (formerly SkyKick)'
            ServicePrincipalType      = 'Application'
            SignInAudience            = 'AzureADMultipleOrgs'
            AccountEnabled            = $true
            AppRoleAssignmentRequired = $false
            PublisherName             = 'SkyKick / ConnectWise'
            VerifiedPublisher         = 'ConnectWise, LLC'
            CreatedDateTime           = $Now.AddDays(-420).ToString('o')
            LastSignInDateTime        = $Now.AddHours(-3).ToString('o')
            Owners                    = @()
            DirectoryRoles            = @(
                [PSCustomObject]@{
                    RoleId          = 'role-exchange-admin'
                    RoleTemplateId  = '29232cdf-9323-42fd-ade2-1d097af3e4de'
                    DisplayName     = 'Exchange Administrator'
                }
            )
            AppRoleAssignments        = @(
                [PSCustomObject]@{ Id = 'ara-101'; Permission = 'Mail.ReadWrite'; ResourceName = 'Microsoft Graph' },
                [PSCustomObject]@{ Id = 'ara-102'; Permission = 'Files.ReadWrite.All'; ResourceName = 'Microsoft Graph' },
                [PSCustomObject]@{ Id = 'ara-103'; Permission = 'Sites.FullControl.All'; ResourceName = 'Microsoft Graph' },
                [PSCustomObject]@{ Id = 'ara-104'; Permission = 'Directory.ReadWrite.All'; ResourceName = 'Microsoft Graph' }
            )
            DelegatedGrants           = @(
                [PSCustomObject]@{ Id = 'grant-101'; ConsentType = 'AllPrincipals'; Scope = 'User.Read Directory.AccessAsUser.All Mail.ReadWrite' }
            )
            PasswordCredentials       = @(
                [PSCustomObject]@{
                    KeyId           = 'bd991122-3344-5566-7788-99aabbccddee'
                    DisplayName     = 'Suspense_Backdoor_Key_Oct2026'
                    StartDateTime   = $Now.AddDays(-4).ToString('o')
                    EndDateTime     = $Now.AddDays(726).ToString('o')
                    SourceObject    = 'ServicePrincipal'
                }
            )
            KeyCredentials            = @()
        },

        # 2. CRITICAL RED: ConnectWise Cloud Management - MS Teams (Privilege Escalation + Can Add Passwords to other Apps)
        [PSCustomObject]@{
            ObjectId                  = 'sp-1002-cw-teams-object-id'
            AppRegistrationObjectId   = $null
            AppId                     = '24205314-2b89-4e07-a2a4-579e898a5640'
            DisplayName               = 'ConnectWise Cloud Management - MS Teams'
            ServicePrincipalType      = 'Application'
            SignInAudience            = 'AzureADMultipleOrgs'
            AccountEnabled            = $true
            AppRoleAssignmentRequired = $false
            PublisherName             = 'ConnectWise'
            VerifiedPublisher         = 'ConnectWise, LLC'
            CreatedDateTime           = $Now.AddDays(-300).ToString('o')
            LastSignInDateTime        = $Now.AddDays(-1).ToString('o')
            Owners                    = @()
            DirectoryRoles            = @(
                [PSCustomObject]@{
                    RoleId          = 'role-global-admin'
                    RoleTemplateId  = '62e90394-69f5-4237-9190-012177145e10'
                    DisplayName     = 'Global Administrator'
                }
            )
            AppRoleAssignments        = @(
                [PSCustomObject]@{ Id = 'ara-201'; Permission = 'RoleManagement.ReadWrite.Directory'; ResourceName = 'Microsoft Graph' },
                [PSCustomObject]@{ Id = 'ara-202'; Permission = 'Application.ReadWrite.All'; ResourceName = 'Microsoft Graph' },
                [PSCustomObject]@{ Id = 'ara-203'; Permission = 'AppRoleAssignment.ReadWrite.All'; ResourceName = 'Microsoft Graph' }
            )
            DelegatedGrants           = @()
            PasswordCredentials       = @()
            KeyCredentials            = @()
        },

        # 3. CRITICAL RED: Internal Legacy Automation App (Can Add Passwords to all Apps + 2 Secrets + Unverified + Long Lifetime)
        [PSCustomObject]@{
            ObjectId                  = 'sp-1003-legacy-sync-id'
            AppRegistrationObjectId   = 'appreg-1003-legacy-sync-id'
            AppId                     = '9911aabb-ccdd-4455-8899-001122334455'
            DisplayName               = 'Contoso-Legacy-IT-Automation-Sync'
            ServicePrincipalType      = 'Application'
            SignInAudience            = 'AzureADMyOrg'
            AccountEnabled            = $true
            AppRoleAssignmentRequired = $false
            PublisherName             = 'Contoso Internal'
            VerifiedPublisher         = $null
            CreatedDateTime           = $Now.AddDays(-600).ToString('o')
            LastSignInDateTime        = $Now.AddDays(-115).ToString('o')
            Owners                    = @()
            DirectoryRoles            = @(
                [PSCustomObject]@{
                    RoleId          = 'role-app-admin'
                    RoleTemplateId  = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'
                    DisplayName     = 'Application Administrator'
                }
            )
            AppRoleAssignments        = @(
                [PSCustomObject]@{ Id = 'ara-301'; Permission = 'Application.ReadWrite.All'; ResourceName = 'Microsoft Graph' },
                [PSCustomObject]@{ Id = 'ara-302'; Permission = 'User.ReadWrite.All'; ResourceName = 'Microsoft Graph' }
            )
            DelegatedGrants           = @()
            PasswordCredentials       = @(
                [PSCustomObject]@{
                    KeyId           = 'sec-301-old'
                    DisplayName     = 'Prod_Secret_2025'
                    StartDateTime   = $Now.AddDays(-350).ToString('o')
                    EndDateTime     = $Now.AddDays(745).ToString('o')
                    SourceObject    = 'Application'
                },
                [PSCustomObject]@{
                    KeyId           = 'sec-302-new'
                    DisplayName     = 'Temp_Debug_Secret'
                    StartDateTime   = $Now.AddDays(-3).ToString('o')
                    EndDateTime     = $Now.AddDays(362).ToString('o')
                    SourceObject    = 'Application'
                }
            )
            KeyCredentials            = @()
        },

        # 4. WARNING ORANGE: Shadow IT OAuth AI Note Taker (Unverified Publisher + Mail.Read / ChannelMessage.Read.All + User Consent)
        [PSCustomObject]@{
            ObjectId                  = 'sp-1004-shadow-ai-notetaker'
            AppRegistrationObjectId   = $null
            AppId                     = '7744ccdd-1122-4e89-9a11-bbccddeeff00'
            DisplayName               = 'SuperAI Meeting & Mail Assistant (Shadow IT)'
            ServicePrincipalType      = 'Application'
            SignInAudience            = 'AzureADMultipleOrgs'
            AccountEnabled            = $true
            AppRoleAssignmentRequired = $false
            PublisherName             = 'Unverified Startup Inc.'
            VerifiedPublisher         = $null
            CreatedDateTime           = $Now.AddDays(-45).ToString('o')
            LastSignInDateTime        = $Now.AddDays(-2).ToString('o')
            Owners                    = @('user-marketing-lead@contoso.de')
            DirectoryRoles            = @()
            AppRoleAssignments        = @(
                [PSCustomObject]@{ Id = 'ara-401'; Permission = 'ChannelMessage.Read.All'; ResourceName = 'Microsoft Graph' }
            )
            DelegatedGrants           = @(
                [PSCustomObject]@{ Id = 'grant-401'; ConsentType = 'Principal'; Scope = 'openid profile User.Read Mail.Read Files.Read.All' }
            )
            PasswordCredentials       = @()
            KeyCredentials            = @()
        },

        # 5. WARNING ORANGE: ConnectWise Cloud Management Base (Already Disabled by Admin, but still on IOC Watchlist)
        [PSCustomObject]@{
            ObjectId                  = 'sp-1005-cw-disabled-id'
            AppRegistrationObjectId   = $null
            AppId                     = '2399d300-6fca-4e6a-a686-399fefe75b83'
            DisplayName               = 'ConnectWise Cloud Management (Base - Contained)'
            ServicePrincipalType      = 'Application'
            SignInAudience            = 'AzureADMultipleOrgs'
            AccountEnabled            = $false
            AppRoleAssignmentRequired = $true
            PublisherName             = 'ConnectWise'
            VerifiedPublisher         = 'ConnectWise, LLC'
            CreatedDateTime           = $Now.AddDays(-500).ToString('o')
            LastSignInDateTime        = $Now.AddDays(-12).ToString('o')
            Owners                    = @('secops@contoso.de')
            DirectoryRoles            = @()
            AppRoleAssignments        = @()
            DelegatedGrants           = @()
            PasswordCredentials       = @()
            KeyCredentials            = @()
        },

        # 6. SECURE GREEN: Hardened SharePoint Selected Intranet Connector (Sites.Selected + Certificate Only + User Assignment Required)
        [PSCustomObject]@{
            ObjectId                  = 'sp-1006-hardened-spo-connector'
            AppRegistrationObjectId   = 'appreg-1006-hardened-spo-connector'
            AppId                     = '11223344-5566-4777-8899-aabbccddeeff'
            DisplayName               = 'Contoso HR Portal Connector (Least Privilege)'
            ServicePrincipalType      = 'Application'
            SignInAudience            = 'AzureADMyOrg'
            AccountEnabled            = $true
            AppRoleAssignmentRequired = $true
            PublisherName             = 'Contoso Enterprise Europe GmbH'
            VerifiedPublisher         = 'Contoso Enterprise Europe GmbH'
            CreatedDateTime           = $Now.AddDays(-120).ToString('o')
            LastSignInDateTime        = $Now.AddHours(-1).ToString('o')
            Owners                    = @('iam-team@contoso.de', 'ciso-office@contoso.de')
            DirectoryRoles            = @()
            AppRoleAssignments        = @(
                [PSCustomObject]@{ Id = 'ara-601'; Permission = 'Sites.Selected'; ResourceName = 'Microsoft Graph' },
                [PSCustomObject]@{ Id = 'ara-602'; Permission = 'User.Read.All'; ResourceName = 'Microsoft Graph' }
            )
            DelegatedGrants           = @(
                [PSCustomObject]@{ Id = 'grant-601'; ConsentType = 'AllPrincipals'; Scope = 'openid profile User.Read' }
            )
            PasswordCredentials       = @()
            KeyCredentials            = @(
                [PSCustomObject]@{
                    KeyId           = 'cert-601-valid'
                    DisplayName     = 'KeyVault-Managed-X509-Cert'
                    StartDateTime   = $Now.AddDays(-60).ToString('o')
                    EndDateTime     = $Now.AddDays(120).ToString('o')
                    SourceObject    = 'Application'
                }
            )
        },

        # 7. WARNING / CRITICAL: Microsoft Graph Command Line Tools (LotL Admin CLI with open user assignment + high-priv delegated scopes)
        [PSCustomObject]@{
            ObjectId                  = 'sp-1007-msgraph-cli-id'
            AppRegistrationObjectId   = $null
            AppId                     = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
            DisplayName               = 'Microsoft Graph Command Line Tools'
            ServicePrincipalType      = 'Application'
            SignInAudience            = 'AzureADMultipleOrgs'
            AccountEnabled            = $true
            AppRoleAssignmentRequired = $false
            PublisherName             = 'Microsoft Corporation'
            VerifiedPublisher         = 'Microsoft Corporation'
            CreatedDateTime           = $Now.AddDays(-390).ToString('o')
            LastSignInDateTime        = $Now.AddHours(-6).ToString('o')
            Owners                    = @()
            DirectoryRoles            = @()
            AppRoleAssignments        = @()
            DelegatedGrants           = @(
                [PSCustomObject]@{ Id = 'grant-701'; ConsentType = 'AllPrincipals'; Scope = 'Directory.ReadWrite.All Application.ReadWrite.All RoleManagement.ReadWrite.Directory openid profile offline_access' }
            )
            PasswordCredentials       = @()
            KeyCredentials            = @()
        }
    )

    return [PSCustomObject]@{
        TenantPoliciesRaw = $TenantPoliciesRaw
        AppsRaw           = $AppsRaw
    }
}

