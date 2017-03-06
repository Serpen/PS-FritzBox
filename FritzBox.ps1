New-Variable -Name AuthRequest -Value ([xml](Get-Content "$PSScriptRoot\ClientAuthRequest.xml" -Encoding UTF8)) -Option ReadOnly,Constant -ea SilentlyContinue
New-Variable -Name InitialRequest -Value ([xml](Get-Content "$PSScriptRoot\initialrequest.xml" -Encoding UTF8)) -Option ReadOnly,Constant -ea SilentlyContinue

$MD5Provider = [System.Security.Cryptography.MD5]::Create()

function New-FBSession {
param (
    [string]$Fritzbox = "fritz.box",
    [string]$Username = "admin",
    [Parameter(Mandatory=$true)][string]$Password,
    [int]$port = 49000
)

[xml]$serviceinfo = Invoke-WebRequest -Method GET -Uri "http://$($FritzBox):$port/tr64desc.xml"

[System.Xml.XmlNamespaceManager]$ns = new-Object System.Xml.XmlNamespaceManager $serviceinfo.NameTable
$ns.AddNamespace("ns",$serviceinfo.DocumentElement.NamespaceURI)
$ns.AddNamespace("h","http://soap-authentication.org/digest/2001/10/")
$ns.AddNamespace("s","http://schemas.xmlsoap.org/soap/envelope/")

$Session = New-Object PSObject -Property (
    [ordered]@{ServiceInfo=$serviceinfo;
    NameSpaceManager=$ns;
    Credentials=New-Object System.Net.NetworkCredential $Username, $Password
    Host="http://$($Fritzbox):$port"})

$Session.psobject.TypeNames.Insert(0,'Serpen.FritzBox.Session')

$portXML = Get-FBSecurityPort $Session

if ([int]::TryParse($portXML.innerText, [ref]$port)) {
    $Session.Host = "https://$($Fritzbox):$port"
}

$Session

} #end function


# MD5 Hashing
function md5([Parameter(Mandatory=$true)][string]$string) {
    [System.BitConverter]::ToString($MD5Provider.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($string))).replace('-','').toLower()
}

# Funktion zum senden eines SOAP Requests
function Execute-SOAPRequest {
param(
    [Parameter(Mandatory=$true)]$Session,
    [Parameter(Mandatory=$true)][String]$URL,
    [Parameter(Mandatory=$true)][string]$action,
    [Parameter(Mandatory=$true)][string]$serviceType,
    [xml]$template = $InitialRequest.Clone(),
    [hashtable]$Parameters = @{}
)

    $WebRequest = [System.Net.WebRequest]::Create("$($Session.Host)$URL")
    $WebRequest.Headers.Add('SOAPAction',"$($serviceType)#$($action)")
    $WebRequest.ContentType = 'text/xml; charset="UTF-8"'
    $WebRequest.Accept      = 'text/xml'
    $WebRequest.Method      = 'POST'

    #only for https
    $WebRequest.ServerCertificateValidationCallback = {$true}

    #used in older fritzbox versions only
    $WebRequest.Credentials = $Session.Credentials

    [Xml]$RequestXML = $template
    [Xml]$responseXML = $null

    $actionNode = $RequestXML.CreateElement('u',$action, $serviceType)
    
    foreach ($param in $Parameters.GetEnumerator()) {
        $newParam = $RequestXML.CreateElement($param.key)
        $newParam.InnerText = $param.value
        $actionNode.AppendChild($newParam) | Out-Null
    }
    $RequestXML.SelectSingleNode("s:Envelope/s:Body", $Session.NameSpaceManager).AppendChild($actionNode) | Out-Null
    
    $RequestXML.Save("$env:temp\fbreq-last.xml")
        
    $requestStream = $WebRequest.GetRequestStream()
    $RequestXML.Save($requestStream)
    $requestStream.Close()

    try {
        [System.IO.StreamReader]$responseStream = $WebRequest.GetResponse().GetResponseStream()
        $responseXML = $responseStream.ReadToEnd()
        $responseStream.Close()
    } catch {
        [xml]$serviceNodeDefinition = Invoke-WebRequest -Uri "$($Session.host)$($serviceNode.SCPDURL)"

        if ($responseXML -eq $null -or ($responseXML.SelectSingleNode("s:Envelope/s:Body/s:Fault", $Session.NameSpaceManager))) {
            $actionNode = $serviceNodeDefinition.scpd.actionList.SelectSingleNode("*[*='$Action']")
            if ($actionNode -eq $null) {
                Write-Error "Action $Action is not defined!"
            } else {
                $paramIn = $actionNode.argumentList.SelectNodes("*[*='in']")
                if ($Parameters.Count -ne $paramIn.count) {
                    Write-Error -Exception [System.ArgumentOutOfRangeException]"Argument count doesn't match"
                } else {
                    if ($paramIn.Count -gt 0 -or $Parameters.Count -gt 0) {
                        Write-Error -Exception [System.ArgumentException]"Argument error"
                    } else {
                        Write-Error -Exception $PSItem.exception -Message "Error [$($PSItem.exception.InnerException.Message)] during SOAP response"
                    }
                } #end else
            } #end else
        } else {
            Write-Error -Exception $PSItem.exception -Message "Error [$($PSItem.exception.Message)] during SOAP response"
        }
        return
        
    } #end catch


    $responseXML.Save("$env:temp\fbres-last.xml")
    $responseXML
}

#create new request with authentication
function CreateAuthRequest {
param (
    [Parameter(Mandatory=$true)]$Session, 
    [Parameter(Mandatory=$true)][xml]$response
)
    $return = $AuthRequest.Clone()

    # read challange data from last response
    $Nonce = $response.SelectSingleNode("s:Envelope/s:Header/h:*/Nonce", $Session.NameSpaceManager)
    $Realm = $response.SelectSingleNode("s:Envelope/s:Header/h:*/Realm", $Session.NameSpaceManager)

    if ($Nonce -eq $null -or $Realm -eq $null) {
        Write-Error "No challenge information" -TargetObject $response -Category AuthenticationError
        return
    }

    $return.Envelope.Header.ClientAuth.Nonce = $Nonce.InnerText
    $return.Envelope.Header.ClientAuth.Realm = $Realm.InnerText 
    $return.Envelope.Header.ClientAuth.UserID = $Session.Credentials.UserName
    $return.Envelope.Header.ClientAuth.Auth = md5 "$(md5 "$($Session.Credentials.UserName):$($Realm.InnerText):$($Session.Credentials.Password)"):$($Nonce.InnerText)"

    return $return
}

function Get-FBActions {
param ([Parameter(Mandatory=$true)]$Session)
    #enumerate all service nodes
    foreach ($service in ($Session.ServiceInfo.SelectNodes("//ns:service", $Session.NameSpaceManager))) {
        
        #load parameter defintion file
        [xml]$xml = Invoke-WebRequest -Uri "$($Session.host)$($service.SCPDURL)"
        
        #enumerate all actions
        foreach ($action in ($xml.scpd.actionList.SelectNodes("*"))) {
            $allINPparams = @()
            $allOUTparams = @()

            #enumerate all parameters i/o
            foreach ($param in ($action.selectNodes("*/*"))) {
                if ($param.direction -eq 'in') {
                    $allINPparams+=($param.name)
                } else {
                    $allOUTparams+=($param.name)
                }
            }
            New-Object PSObject -Property ([ordered]@{Service=$service.serviceType;Action=$action.name; ParameterOut=$allOUTparams; ParameterIn=$allINPparams}) 
        }
    }
}

function Invoke-FBAction {
param (
    [Parameter(Mandatory=$true) ]$Session,
    [Parameter(Mandatory=$true) ]$service,
    [Parameter(Mandatory=$true) ]$Action,
    [Parameter(Mandatory=$false)]$Parameters = @{}
)
    # search for matching service entry
    #$serviceNode = $Session.serviceinfo.SelectNodes("//*[*='$service']")
    $serviceNode = $Session.serviceinfo.SelectNodes(([string]"//ns:service[ns:serviceType='$service']"), ([System.Xml.XmlNamespaceManager]$Session.NameSpaceManager))

    if ($serviceNode.count -eq 0) {
        Write-Error "no Service '$service' found"
        return
    }

    [xml]$requestXML = $InitialRequest.clone()
    [xml]$responseXML = $null
    [xml]$authRequestXML = $null

    # perform unauthenticated request
    $responseXML = Execute-SOAPRequest -template $requestXML $serviceNode.controlURL -session $Session -action $action -serviceType $serviceNode.serviceType -Parameters $Parameters

    if ($responseXML -eq $null) {
        return
    }
    
    # check if request needs to be resend authenticated
    if (($responseXML).SelectSingleNode("//Status[text()='Unauthenticated']")) {
        
        $authRequestXML = CreateAuthRequest -response $responseXML -session $Session
    
        # perform authenticated request
        $responseXML = Execute-SOAPRequest -template $authRequestXML $serviceNode.controlURL -session $Session -action $action -serviceType $serviceNode.serviceType -Parameters $Parameters

        if ($responseXML -eq $null) {
            return
        }
    }
    return $responseXML.SelectSingleNode("s:Envelope/s:Body/*", $Session.NameSpaceManager)
}

function Invoke-FBEnumeration {
param (
    [Parameter(Mandatory=$true)]$Session,
    [Parameter(Mandatory=$true)][string]$Service = 'urn:dslforum-org:service:Hosts:1',
    [Parameter(Mandatory=$true)][string]$ActionCount = 'GetHostNumberOfEntries',
    [Parameter(Mandatory=$true)][string]$Action  = 'GetGenericHostEntry',
    [Parameter(Mandatory=$true)][string]$IndexParam = 'NewIndex'
)
    [System.Xml.XmlElement]$countXML = (Invoke-FBAction -Session $Session -Service $Service -Action $ActionCount)
    [int]$count = 0

    if ([int]::TryParse($countXML.InnerText, [ref]$count)) {
        for ([int]$i = 0; $i -lt $count; $i++) {
            Invoke-FBAction -Session $Session -Service $Service -Action $Action -Parameters @{"$IndexParam"=$i}
        }
    }
}

function Get-FBSecurityPort {
param ([Parameter(Mandatory=$true)]$Session)
    Invoke-FBAction -Session $Session -Service 'urn:dslforum-org:service:DeviceInfo:1' -Action 'GetSecurityPort'
}

function Get-FBInfo{
param ([Parameter(Mandatory=$true)]$Session)
    $Service = 'urn:dslforum-org:service:DeviceInfo:1'
    $action = 'GetInfo'

    Invoke-FBAction -session $Session -Service $Service -action $action
}

function Get-FBCallList {
param ([Parameter(Mandatory=$true)]$Session)
    
    $Url2List = Invoke-FBAction -Session $Session -Service 'urn:dslforum-org:service:X_AVM-DE_OnTel:1' -Action 'GetCallList'

    [xml]$CallList = Invoke-WebRequest -Uri $Url2List.NewCallListURL

    $CallList.root.Call
}

