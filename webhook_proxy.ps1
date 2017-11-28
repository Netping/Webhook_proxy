Add-Type -AssemblyName System.Web

#Debug options
#----------------------------
$DebugPreference = "Continue" # turn debug on 
#$DebugPreference = "SilentlyContinue" # turn debug off
Set-Variable -Name DEBUG_INFO -Value 0 -Option Constant -ErrorAction SilentlyContinue
Set-Variable -Name DEBUG_ERROR -Value 1 -Option Constant -ErrorAction SilentlyContinue
Remove-Variable -Name DEBUG_ID -Force -ErrorAction SilentlyContinue  #need only for ISE unical numbers every session
Set-Variable -Name DEBUG_ID -Value (Get-Random -minimum 1000 -maximum 9999) -Option ReadOnly -ErrorAction SilentlyContinue
Set-Variable -Name DEBUG_FILE_PATH -Value "C:\Program Files (x86)\Syslogd\Scripts\webhook_proxy_debug.txt" -Option Constant -ErrorAction SilentlyContinue # !!! if change need restart powershell session !!!


#Constants
# ---------------------------
Set-Variable -Name LOG_FILE_PATH -Value "C:\Share\webhook_proxy_log.txt" -Option Constant -ErrorAction SilentlyContinue # !!! if change need restart powershell session !!!



# ---------------------------
function DebugOutput ($message="",$type=$DEBUG_INFO)
{
    if ($DebugPreference -ne "Continue") { exit }

    $datetime= Get-Date
    $message="ID:"+$DEBUG_ID.ToString() + " " + $datetime.ToShortDateString() + " "+ $datetime.ToLongTimeString()+" " +  $message
    if ($type -eq $DEBUG_ERROR) {$message="ERROR: " +$message}
    Write-Debug $message
    Add-Content $DEBUG_FILE_PATH $message -Force

}


DebugOutput "Script was started"
DebugOutput ("Command line parameters:"+$args.Count.ToString()+" "+"Param0: "+$args[0] + "Param1: "+$args[1] + "Param2: "+$args[2] + "Param3: "+$args[3] + "Param4: "+ $args[4] + "Param5: "+ $args[5] + "Param6: "+ $args[6])



# Check parametrs count according to docs
if ($args.Count -lt 5) {
   DebugOutput  "Incorrect number of parameters, pls see: https://netping.atlassian.net/wiki/pages/viewpage.action?pageId=105234720"
   exit
}

#Check if supported Enterprise OID is exist
if (-not($args[4] -like "*enterprise=1.3.6.1.4.1.25728.9900.3.0.1*") -and -not($args[4] -like "*enterprise=1.3.6.1.4.1.25728.3800.2.0.3*") ) {
   DebugOutput "Supported interprise OID was not found, pls see: https://netping.atlassian.net/wiki/pages/viewpage.action?pageId=105234351"
   exit
}


$Msg_Info = @{}

try 
{

DebugOutput "Supported OIDs was founded"

#Extract common parameters 1-5 as https://netping.atlassian.net/wiki/pages/viewpage.action?pageId=105234720
$Msg_Info.Add("DateTime",[datetime]($args[0].ToString() + " " + $args[1].ToString()))
$Msg_Info.Add("Priority",$args[2].ToString())
$Msg_Info.Add("SourceIP",[System.Net.IPAddress]$args[3].ToString())


$msg=$args[4]

for ($i=5; $i -lt $args.Count; $i++)
{
 $msg=$msg+ "" + $args[$i]
}
$msg=[System.Web.HttpUtility]::UrlDecode($msg,[System.Text.Encoding]::GetEncoding(1251))
$msg=$msg.Replace("`n","")
$Msg_Info.Add("RawMessage",$msg)

DebugOutput ("Raw message: " +$msg)
DebugOutput ("`n" +$Msg_Info.Values)
 


#Extract parameters from RawMessage
$Msg_Info.Add("Community",[regex]::Match($Msg_Info.RawMessage,'^community=(\S+)').Groups[1].Value)
$Msg_Info.Add("AgentIP",[System.Net.IPAddress]([regex]::Match($Msg_Info.RawMessage,'^*agent_ip=(\S+)').Groups[1].Value))
$Msg_Info.Add("UPTime",[int]([regex]::Match($Msg_Info.RawMessage,'^*uptime=(\S+)').Groups[1].Value))
$Msg_Info.Add("Enterprise",[string]([regex]::Match($Msg_Info.RawMessage,'^*enterprise=(\S+)').Groups[1].Value))
$Msg_Info.Add("Version",[string]([regex]::Match($Msg_Info.RawMessage,'^*version=(\S+)').Groups[1].Value))

DebugOutput ("`n" + $Msg_Info.Values)

$internalOIDSRaw=Select-String -InputObject $Msg_Info.RawMessage -Pattern '(3\.6.*?)=(.*?)((\s1\.)|$)' -AllMatches | Foreach-Object {$_.Matches} 
for ($i=1; $i -lt $internalOIDSRaw.Count; $i++){
    $Msg_Info.Add("1."+$internalOIDSRaw[$i].Groups[1].Value,   $internalOIDSRaw[$i].Groups[2].Value)
}


#Get TRAP type specific information

# From DKSF 70 and others
if ($Msg_Info.ContainsKey("1.3.6.1.4.1.25728.9900.3.3.0")) {
    DebugOutput "OID 1.3.6.1.4.1.25728.9900.3.3.0 was found"
    $msg=$Msg_Info["1.3.6.1.4.1.25728.9900.3.3.0"].ToString()

    #Extract HTTP destination address
    $Msg_Info.Add("URL",[System.Uri]([regex]::Match($msg,'https?://\S+')).ToString())
    DebugOutput ("Was found URL: " + $Msg_Info.URL)

    #Extract Full Webhook Message
    $Msg_Info.Add("FullWebhookMessage",$msg.Replace($Msg_Info.URL.OriginalString,"").TrimStart(" "))
    DebugOutput ("Webhook message: " + $Msg_Info.FullWebhookMessage)
          
    #Extract addationally parameters inside message https://netping.atlassian.net/wiki/pages/viewpage.action?pageId=105234351 (TRAP о событиях на датчиках)
    $keys=Select-String -InputObject $msg -Pattern '\w+=' -AllMatches | Foreach-Object {$_.Matches} 
    for ($i=0; $i -lt $keys.Count; $i++){
        if ($i -lt ($keys.Count-1)) {
            $val=$msg.Substring($keys[$i].Index+$keys[$i].Length,$keys[$i+1].Index-$keys[$i].Index-$keys[$i].Length-1)
        } else {
            $val=$msg.Substring($keys[$i].Index+$keys[$i].Length,$msg.Length-$keys[$i].Index-$keys[$i].Length)
        }
        DebugOutput ("Was fond key: " + $keys[$i].Value  + $val)
        $Msg_Info.Add("int_"+$keys[$i].Value.TrimEnd(1,'='),$val)
    } 
    
}

# From NetPing SMS
if ($Msg_Info.ContainsKey("1.3.6.1.4.1.25728.3800.1.12.0")) {
    DebugOutput "1.3.6.1.4.1.25728.3800.1.12.0 was found"

    #Extract HTTP destination address
    $Msg_Info.Add("URL",[System.Uri]([regex]::Match($Msg_Info.'1.3.6.1.4.1.25728.95.31.0','https?://\S+')).ToString())
    DebugOutput ("Was found URL: " + $Msg_Info.URL)

    #Extract SYS NAME as additional parametr
    $Msg_Info.Add("sysName",[string]([regex]::Match($Msg_Info.'1.3.6.1.4.1.25728.95.31.0','sysName\.0=(\S+)')).Groups[1])
    DebugOutput ("Was found sysName: " + $Msg_Info.sysName)

    #Extract Full Webhook Message
    $Msg_Info.Add("FullWebhookMessage",[string]$Msg_Info.'1.3.6.1.4.1.25728.3800.1.12.0')
    DebugOutput ("Webhook message: " + $Msg_Info.FullWebhookMessage + " (from: " + $Msg_Info.InMessageParams.sysName + ")")
}



#Send HTTP POST
$body=@{}
$Msg_Info.Keys | Where-Object {$_ -notin ("Priority", "Version","SourceIP","RawMessage","URL","Community")} | ForEach-Object {$body.Add($_,$Msg_Info[$_].ToString())} 
$body=$body | ConvertTo-Json 
$body=$body -replace '[\x80-\xB0]+',''

DebugOutput ("Send HTTP webhook to host: "+ $Msg_Info.URL.ToString())
DebugOutput ("Body: "+ $body)

$res=Invoke-WebRequest -Uri $Msg_Info.URL -Method Post -ContentType "application/json" -Headers @{'Accept'="application/json"} -Body $body

$message='"'+$Msg_Info.DateTime.ToShortDateString()+'","'+$Msg_Info.DateTime.ToLongTimeString()+'","'+$Msg_Info.SourceIP.ToString()+'","'+$Msg_Info.AgentIP.ToString()+'","'+$Msg_Info.URL.ToString()+'","OK",""'
Add-Content $LOG_FILE_PATH $message -Force


} catch
{
    DebugOutput $_ $DEBUG_ERROR

    $msg_date=""
    $msg_date=try{$Msg_Info.DateTime.ToShortDateString()}catch{}
    $msg_time=""
    $msg_time=try{$Msg_Info.DateTime.ToLongTimeString()}catch{}
    $msg_source_ip=""
    $msg_source_ip=try{$Msg_Info.SourceIP.ToString()}catch{}
    $msg_agent_ip=""
    $msg_agent_ip=try{$Msg_Info.AgentIP.ToString()}catch{}
    $msg_url=""
    $msg_url=try{$Msg_Info.URL.ToString()}catch{}
    $message='"'+$msg_date+'","'+$msg_time+'","'+$msg_source_ip+'","'+$msg_agent_ip+'","'+$msg_url+'","ERROR","'+([string]$_).Replace('"',"")+'"'
    Add-Content $LOG_FILE_PATH $message -Force

}



