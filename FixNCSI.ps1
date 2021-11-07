# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# #                                                                                                   # # 
# #                                                                                                   # # 
# #                                  Windows 10 NCSI Fix (Fix Globe)                                  # # 
# #                                        by Gabriel Polmar                                          # # 
# #                                        Megaphat Networks                                          # # 
# #                                        www.megaphat.info                                          # #
# #                                                                                                   # # 
# #                                                                                                   # #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 


Function Say($something) {
	Write-Host $something 
}

Function SayN($something) {
	#Say something, anything!
	Write-Host $something  -NoNewLine
}

Function SayB($something) {
	Write-Host $something -ForegroundColor darkblue -BackgroundColor white
}

Function Get-KeyInput() {
	$key = ([string]($Host.UI.RawUI.ReadKey()).character).ToLower()
	Return $key
}

Function isAdminLocal {
	$ret = (new-object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole("Administrators")
	Return $ret
}

Function isElevated {
	$ret = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
	Return $ret
}

Function regSet ($KeyPath, $KeyItem, $KeyValue) {
	$Key = $KeyPath.Split("\")
	ForEach ($level in $Key) {
		If (!($ThisKey)) {
			$ThisKey = "$level"
		} Else {
			$ThisKey = "$ThisKey\$level"
		}
		If (!(Test-Path $ThisKey)) {New-Item $ThisKey -Force -ErrorAction SilentlyContinue | out-null}
	}
	Set-ItemProperty $KeyPath $KeyItem -Value $KeyValue -ErrorAction SilentlyContinue 
}

Function regGet($Key, $Item) {
	If (!(Test-Path $Key)) {
		Return
	} Else {
		If (!($Item)) {$Item = "(Default)"}
		$ret = (Get-ItemProperty -Path $Key -Name $Item -ErrorAction SilentlyContinue).$Item
		Return $ret
	}
}

Function beAggressive() {
	SayN "Executing Be Aggressive..."
	Remove-Item "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -erroraction silentlycontinue
	regSet "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" "Value" "1"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -erroraction silentlycontinue
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" "1"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -erroraction silentlycontinue
	regSet "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" "1"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" "0"
	regSet "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" "Status" "0"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" "Value" "Deny"
	regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" "0"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice\AllowFindMyDevice" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Speech" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows Mail" -erroraction silentlycontinue
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" "0"
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableCdp" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\DataCollection\AllowTelemetry" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSync" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSyncUserOverride" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\MRT\DontReportInfectionInformation" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -erroraction silentlycontinue
	Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters\Type" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\EnableFontProviders" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Suggested Sites" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "DisableTelemetryOptInChangeNotification" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "ConfigureTelemetryOptInChangeNotification" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "DisableTelemetryOptInSettingsUx" -erroraction silentlycontinue
	regSet "HKLM:\System\CurrentControlSet\Services\wlidsvc" "Start" "3"
	Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\Messaging" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -erroraction silentlycontinue
	regSet "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SubmitSamplesConsent" "1"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SpyNetReporting" "2"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SpyNetReportingLocation" "SOAP:https://wdcp.microsoft.com/WdCpSrvc.asmx SOAP:https://wdcpalt.microsoft.com/WdCpSrvc.asmx REST:https://wdcp.microsoft.com/wdcp.svc/submitReport REST:https://wdcpalt.microsoft.com/wdcp.svc/submitReport BOND:https://wdcp.microsoft.com/wdcp.svc/bond/submitreport BOND:https://wdcpalt.microsoft.com/wdcp.svc/bond/submitreport"
	Remove-Item "HKLM:\Software\Policies\Microsoft\MRT" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet\SpyNetReporting" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableAppUriHandlers" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -erroraction silentlycontinue
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanInterfaceDevice" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\sensors.custom" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\serialCommunication" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\usb" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" "Value" "Allow"
	regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wiFiDirect" "Value" "Allow"
	Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" -erroraction silentlycontinue
	Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -erroraction silentlycontinue
	Remove-Item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -recurse -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -erroraction silentlycontinue
	Remove-Item "HKCU:\Software\Microsoft\Siuf\Rules" -erroraction silentlycontinue
	regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "ContentDeliveryAllowed" "1"
	regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "OemPreInstalledAppsEnabled" "1"
	regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEnabled" "1"
	regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEverEnabled" "1"
	regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" "1"
	regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" "1"
	Remove-Item "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -erroraction silentlycontinue
	regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic" "FirstRunSucceeded" "0"
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -erroraction silentlycontinue
	regSet "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" "1"
	regSet "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" "1"
	regSet "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" "0"
	regSet "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" "0"
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -erroraction silentlycontinue
	Remove-Item "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -erroraction silentlycontinue
	Remove-Item "HKCU:\Software\Microsoft\Siuf\Rules\PeriodInNanoSeconds" -erroraction silentlycontinue
	Remove-Item "HKCU:\Software\Microsoft\Siuf\Rules\NumberOfSIUFInPeriod" -erroraction silentlycontinue
	Remove-Item "HKCU:\SOFTWARE\Microsoft\Messaging" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -erroraction silentlycontinue
	Remove-Item "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\Main" -erroraction silentlycontinue
	regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" "Value" "Allow"
	regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" "Value" "Allow"
	Remove-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" -erroraction silentlycontinue
	Remove-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" -erroraction silentlycontinue
	regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" "Value" "Allow"
	regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" "Value" "Allow"
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "DisablePassivePolling" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "UseGlobalDns" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -erroraction silentlycontinue
	regSet "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" "EnableActiveProbing" "1"
	regSet "HKLM:\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet" "ActiveDnsProbeContent" "131.107.255.255"
	regSet "HKLM:\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet" "ActiveDnsProbeHost" "dns.msftncsi.com"
	regSet "HKLM:\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet" "ActiveWebProbeContent" "Microsoft Connect Test"
	regSet "HKLM:\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet" "ActiveWebProbeHost" "www.msftconnecttest.com"
	regSet "HKLM:\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet" "ActiveWebProbePath" "connecttest.txt"
	regSet "HKLM:\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet" "EnableActiveProbing" "1"
	Say "Be Aggressive Execution Completed!"
}

Function beNormal() {
	SayN "Executing Be Normal..."
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "DisablePassivePolling" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "UseGlobalDns" -erroraction silentlycontinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -erroraction silentlycontinue
	regSet "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" "EnableActiveProbing" "1"
	regSet "HKLM:\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet" "ActiveDnsProbeContent" "131.107.255.255"
	regSet "HKLM:\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet" "ActiveDnsProbeHost" "dns.msftncsi.com"
	regSet "HKLM:\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet" "ActiveWebProbeContent" "Microsoft Connect Test"
	regSet "HKLM:\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet" "ActiveWebProbeHost" "www.msftconnecttest.com"
	regSet "HKLM:\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet" "ActiveWebProbePath" "connecttest.txt"
	regSet "HKLM:\SYSTEM\ControlSet001\Services\NlaSvc\Parameters\Internet" "EnableActiveProbing" "1"
	Say "Be Normal Execution Completed!"
}

Function Get-Selection() {
	cls
	Say "Windows 10 NCSI Fix Menu"
	Say "========================="
	Say ""
	Say "0 - Quit"
	Say "1 - Run in Normal Mode"
	Say "2 - Run in Aggressive Mode"
	SayN "Enter Selection: "
	$ki = Get-KeyInput
	Return $ki
}

Function Get-Restart() {
	$ready = $false
	While ($ready -eq $false) {
		Say "You will need to restart this computer in order for the changes to take effect."
		Say "Do you want to restart your computer now? (Y/N)"
		$ki = (Get-KeyInput).toLower()
		If ($ki -eq "y") {
			Say " - Restarting..."
			Restart-Computer -force
			$ready=$true
		} ElseIf ($ki -eq "n") {
			Say " - Not Restarting Now..."
			$ready=$true
		} Else {Say " - Invalid Response."}
	}
}
If (!(isAdminLocal)) {
	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`" elevate" -f $PSCommandPath) -Verb RunAs
	Exit
}

If (!(isElevated)) {
	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`" elevate" -f $PSCommandPath) -Verb RunAs
	Exit
}

$CanDo = "x"
cls
While ($CanDo -ne "z") {
	$CanDo = Get-Selection
	switch ($CanDo) {
		0 {$CanDo = "z"}
		1 { SayB "Executing NCSI Fix in Normal Mode."
			beNormal
			Say "NCSI Normal Mode Fix has been applied."
			Get-Restart
			$CanDo = "z"}
		2 { SayB "Executing NCSI Fix in Aggressive Mode."
			beAggressive
			beNormal
			Say "NCSI Aggressive Mode Fix has been applied."
			Get-Restart
			$CanDo = "z"}
		else {Say "Invalid Option"}
	}
}			



