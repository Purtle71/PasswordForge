\
<#
PasswordForge
Local password strength rater, improver, and generator for Windows.

Run:
  powershell -ExecutionPolicy Bypass -File .\PasswordForge.ps1

Passwords are analyzed locally. The application does not transmit or save them.
#>

#region Assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Security
#endregion

#region Globals
$Script:SimilarChars = "Il1O0o"
$Script:UpperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
$Script:LowerChars = "abcdefghijklmnopqrstuvwxyz"
$Script:NumberChars = "0123456789"
$Script:SymbolChars = "!@#$%^&*()-_=+[]{};:,.?/"
$Script:CommonPasswords = @(
    "password","password1","passw0rd","p@ssword","123456","12345678","123456789",
    "qwerty","qwerty123","admin","admin123","welcome","welcome1","letmein",
    "iloveyou","monkey","dragon","football","baseball","abc123","111111",
    "123123","trustno1","sunshine","princess","login","master","hello",
    "freedom","whatever","password123"
)
$Script:KeyboardPatterns = @("qwerty","asdf","zxcv","1qaz","2wsx","qazwsx","poiuy","lkjh","mnbv")
$Script:Sequences = @("0123","1234","2345","3456","4567","5678","6789","abcd","bcde","cdef","defg","wxyz")
$Script:WordBank = @(
    "anchor","bison","cobalt","delta","ember","falcon","galaxy","harbor","iron","jungle",
    "kernel","lantern","matrix","nova","onyx","prairie","quartz","raven","signal","tundra",
    "umbra","vector","warden","xenon","yonder","zenith","atlas","bridge","cipher","drift",
    "echo","forge","glacier","hazel","island","jacket","kepler","legend","mortar","nectar",
    "orbit","pillar","rocket","silver","titan","uplink","velvet","whisper","yard","zephyr"
)
#endregion

#region Random Helpers
function Get-SecureInt {
    param([int]$MaxExclusive)
    if ($MaxExclusive -le 0) { return 0 }
    $bytes = New-Object byte[] 4
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        do {
            $rng.GetBytes($bytes)
            $value = [BitConverter]::ToUInt32($bytes, 0)
            $limit = [uint32]::MaxValue - ([uint32]::MaxValue % [uint32]$MaxExclusive)
        } while ($value -ge $limit)
        return [int]($value % [uint32]$MaxExclusive)
    } finally {
        $rng.Dispose()
    }
}

function Get-RandomCharFromSet {
    param([string]$Set)
    if ([string]::IsNullOrEmpty($Set)) { return "" }
    $idx = Get-SecureInt $Set.Length
    return [string]$Set[$idx]
}

function Shuffle-String {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    $chars = New-Object System.Collections.Generic.List[char]
    foreach ($c in $Text.ToCharArray()) { [void]$chars.Add($c) }
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $j = Get-SecureInt ($i + 1)
        $tmp = $chars[$i]
        $chars[$i] = $chars[$j]
        $chars[$j] = $tmp
    }
    return (-join $chars.ToArray())
}

function Remove-SimilarCharacters {
    param([string]$Set)
    $out = New-Object System.Text.StringBuilder
    foreach ($c in $Set.ToCharArray()) {
        if ($Script:SimilarChars.IndexOf([string]$c) -lt 0) { [void]$out.Append($c) }
    }
    return $out.ToString()
}

function Get-CharPool {
    param(
        [bool]$UseUpper,
        [bool]$UseLower,
        [bool]$UseNumbers,
        [bool]$UseSymbols,
        [bool]$ExcludeSimilar
    )
    $pool = ""
    if ($UseUpper) { $pool += $Script:UpperChars }
    if ($UseLower) { $pool += $Script:LowerChars }
    if ($UseNumbers) { $pool += $Script:NumberChars }
    if ($UseSymbols) { $pool += $Script:SymbolChars }
    if ($ExcludeSimilar) { $pool = Remove-SimilarCharacters $pool }
    return $pool
}
#endregion

#region Password Logic
function Estimate-Entropy {
    param([string]$Password)
    if ([string]::IsNullOrEmpty($Password)) { return 0 }
    $pool = 0
    if ($Password -cmatch '[a-z]') { $pool += 26 }
    if ($Password -cmatch '[A-Z]') { $pool += 26 }
    if ($Password -match '\d') { $pool += 10 }
    if ($Password -match '[^a-zA-Z0-9]') { $pool += 32 }
    if ($pool -le 1) { return 0 }
    $entropy = $Password.Length * ([Math]::Log($pool) / [Math]::Log(2))
    return [Math]::Round($entropy, 1)
}

function Test-Sequence {
    param([string]$Password)
    if ([string]::IsNullOrEmpty($Password)) { return $false }
    $p = $Password.ToLowerInvariant()
    foreach ($s in $Script:Sequences) {
        if ($p.Contains($s)) { return $true }
        $revChars = $s.ToCharArray()
        [Array]::Reverse($revChars)
        $rev = -join $revChars
        if ($p.Contains($rev)) { return $true }
    }
    return $false
}

function Get-PasswordAnalysis {
    param([string]$Password)
    $suggestions = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $checks = New-Object System.Collections.Generic.List[object]

    if ($null -eq $Password) { $Password = "" }
    $length = $Password.Length
    $hasLower = ($Password -cmatch '[a-z]')
    $hasUpper = ($Password -cmatch '[A-Z]')
    $hasNumber = ($Password -match '\d')
    $hasSymbol = ($Password -match '[^a-zA-Z0-9]')
    $entropy = Estimate-Entropy $Password

    $score = 0
    if ($length -ge 8) { $score += 15 } else { [void]$suggestions.Add("Use at least 8 characters. 14 or more is better.") }
    if ($length -ge 12) { $score += 15 } else { [void]$suggestions.Add("Increase the length to 12 or more characters.") }
    if ($length -ge 16) { $score += 10 }
    if ($hasLower) { $score += 10 } else { [void]$suggestions.Add("Add lowercase letters.") }
    if ($hasUpper) { $score += 10 } else { [void]$suggestions.Add("Add uppercase letters.") }
    if ($hasNumber) { $score += 10 } else { [void]$suggestions.Add("Add numbers.") }
    if ($hasSymbol) { $score += 10 } else { [void]$suggestions.Add("Add symbols such as !, @, #, or %." ) }
    if ($entropy -ge 70) { $score += 20 } elseif ($entropy -ge 45) { $score += 10 } else { [void]$suggestions.Add("Use more length and character variety to raise entropy.") }

    $lower = $Password.ToLowerInvariant()
    foreach ($common in $Script:CommonPasswords) {
        if ($lower -eq $common -or ($lower.Contains($common) -and $common.Length -ge 5)) {
            $score -= 35
            [void]$warnings.Add("Contains a common password or common word: $common")
            [void]$suggestions.Add("Remove common words like '$common'.")
            break
        }
    }
    foreach ($pattern in $Script:KeyboardPatterns) {
        if ($lower.Contains($pattern)) {
            $score -= 20
            [void]$warnings.Add("Contains keyboard pattern: $pattern")
            [void]$suggestions.Add("Avoid keyboard patterns like qwerty or asdf.")
            break
        }
    }
    if (Test-Sequence $Password) {
        $score -= 15
        [void]$warnings.Add("Contains a sequence such as 1234 or abcd")
        [void]$suggestions.Add("Avoid number or letter sequences.")
    }
    if ($Password -match '(.)\1\1') {
        $score -= 15
        [void]$warnings.Add("Contains repeated characters")
        [void]$suggestions.Add("Avoid repeated characters like aaa or 111.")
    }
    if ($Password -match '^[A-Za-z]+\d{1,4}$') {
        $score -= 15
        [void]$warnings.Add("Looks like a word with numbers added to the end")
        [void]$suggestions.Add("Do not just add numbers to the end of a word.")
    }
    if ($Password -match '(19|20)\d{2}') {
        $score -= 10
        [void]$warnings.Add("Contains a year")
        [void]$suggestions.Add("Avoid years or dates.")
    }

    $score = [Math]::Max(0, [Math]::Min(100, $score))
    $rating = "Very Weak"
    if ($score -ge 85) { $rating = "Very Strong" }
    elseif ($score -ge 70) { $rating = "Strong" }
    elseif ($score -ge 50) { $rating = "Fair" }
    elseif ($score -ge 30) { $rating = "Weak" }

    if ($suggestions.Count -eq 0) { [void]$suggestions.Add("This password meets the local strength checks.") }
    if ($warnings.Count -eq 0) { [void]$warnings.Add("No major local pattern warnings found.") }

    [void]$checks.Add([pscustomobject]@{ Requirement="At least 12 characters"; Status= $(if($length -ge 12){"Pass"}else{"Fail"}) })
    [void]$checks.Add([pscustomobject]@{ Requirement="At least 16 characters"; Status= $(if($length -ge 16){"Pass"}else{"Optional"}) })
    [void]$checks.Add([pscustomobject]@{ Requirement="Uppercase letter"; Status= $(if($hasUpper){"Pass"}else{"Fail"}) })
    [void]$checks.Add([pscustomobject]@{ Requirement="Lowercase letter"; Status= $(if($hasLower){"Pass"}else{"Fail"}) })
    [void]$checks.Add([pscustomobject]@{ Requirement="Number"; Status= $(if($hasNumber){"Pass"}else{"Fail"}) })
    [void]$checks.Add([pscustomobject]@{ Requirement="Symbol"; Status= $(if($hasSymbol){"Pass"}else{"Fail"}) })
    [void]$checks.Add([pscustomobject]@{ Requirement="No common or repeated pattern"; Status= $(if($warnings[0] -eq "No major local pattern warnings found."){"Pass"}else{"Fail"}) })

    return [pscustomobject]@{
        Score=$score
        Rating=$rating
        Entropy=$entropy
        Length=$length
        Suggestions=$suggestions.ToArray()
        Warnings=$warnings.ToArray()
        Checks=$checks.ToArray()
    }
}

function New-StrongPassword {
    param(
        [int]$Length = 20,
        [bool]$UseUpper = $true,
        [bool]$UseLower = $true,
        [bool]$UseNumbers = $true,
        [bool]$UseSymbols = $true,
        [bool]$ExcludeSimilar = $true
    )
    if ($Length -lt 8) { $Length = 8 }
    $pool = Get-CharPool $UseUpper $UseLower $UseNumbers $UseSymbols $ExcludeSimilar
    if ([string]::IsNullOrEmpty($pool)) {
        $pool = Remove-SimilarCharacters ($Script:UpperChars + $Script:LowerChars + $Script:NumberChars + $Script:SymbolChars)
    }

    $chars = New-Object System.Collections.Generic.List[string]
    if ($UseUpper) {
        $set = $Script:UpperChars
        if ($ExcludeSimilar) { $set = Remove-SimilarCharacters $set }
        if ($set.Length -gt 0) { [void]$chars.Add((Get-RandomCharFromSet $set)) }
    }
    if ($UseLower) {
        $set = $Script:LowerChars
        if ($ExcludeSimilar) { $set = Remove-SimilarCharacters $set }
        if ($set.Length -gt 0) { [void]$chars.Add((Get-RandomCharFromSet $set)) }
    }
    if ($UseNumbers) {
        $set = $Script:NumberChars
        if ($ExcludeSimilar) { $set = Remove-SimilarCharacters $set }
        if ($set.Length -gt 0) { [void]$chars.Add((Get-RandomCharFromSet $set)) }
    }
    if ($UseSymbols) {
        [void]$chars.Add((Get-RandomCharFromSet $Script:SymbolChars))
    }

    while ($chars.Count -lt $Length) { [void]$chars.Add((Get-RandomCharFromSet $pool)) }
    return (Shuffle-String (-join $chars.ToArray()))
}

function New-Passphrase {
    param([int]$Words = 4, [string]$Delimiter = "-", [bool]$AddNumber = $true, [bool]$AddSymbol = $true)
    if ($Words -lt 3) { $Words = 3 }
    $parts = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $Words; $i++) {
        [void]$parts.Add($Script:WordBank[(Get-SecureInt $Script:WordBank.Count)])
    }
    $phrase = ($parts.ToArray() -join $Delimiter)
    if ($AddNumber) { $phrase += [string]((Get-SecureInt 9000) + 1000) }
    if ($AddSymbol) { $phrase += (Get-RandomCharFromSet "!@#$%&*") }
    return $phrase
}

function Strengthen-Password {
    param([string]$Password, [int]$TargetLength = 20, [bool]$Readable = $true)
    if ($TargetLength -lt 12) { $TargetLength = 12 }
    if ([string]::IsNullOrWhiteSpace($Password)) { return (New-StrongPassword -Length $TargetLength) }

    $map = @{ 'a'='@'; 'e'='3'; 'i'='!'; 'o'='0'; 's'='$'; 't'='7' }
    $out = New-Object System.Text.StringBuilder
    $changed = 0
    foreach ($c in $Password.ToCharArray()) {
        $key = ([string]$c).ToLowerInvariant()
        if ($map.ContainsKey($key) -and $changed -lt 3 -and (Get-SecureInt 2) -eq 1) {
            [void]$out.Append($map[$key])
            $changed++
        } else {
            [void]$out.Append($c)
        }
    }

    $result = $out.ToString()
    if ($result.Length -eq 0) { $result = New-StrongPassword -Length $TargetLength }
    if ($result -cnotmatch '[A-Z]') {
        $first = $result.Substring(0,1).ToUpperInvariant()
        if ($result.Length -gt 1) { $result = $first + $result.Substring(1) } else { $result = $first }
    }
    if ($result -cnotmatch '[a-z]') { $result += (Get-RandomCharFromSet $Script:LowerChars) }
    if ($result -notmatch '\d') { $result += [string]((Get-SecureInt 90) + 10) }
    if ($result -notmatch '[^a-zA-Z0-9]') { $result += (Get-RandomCharFromSet "!@#$%&*") }

    if ($Readable) {
        while ($result.Length -lt $TargetLength) {
            $word = $Script:WordBank[(Get-SecureInt $Script:WordBank.Count)]
            $result += "-" + $word
        }
    } else {
        while ($result.Length -lt $TargetLength) {
            $remaining = $TargetLength - $result.Length
            $addLen = [Math]::Min(8, $remaining)
            $result += (New-StrongPassword -Length $addLen -UseUpper $true -UseLower $true -UseNumbers $true -UseSymbols $true -ExcludeSimilar $true)
        }
        $result = Shuffle-String $result
    }

    if ($result.Length -gt ($TargetLength + 18)) { $result = $result.Substring(0, ($TargetLength + 18)) }
    return $result
}
#endregion

#region UI Setup
[System.Windows.Forms.Application]::EnableVisualStyles()
$fontMain = New-Object System.Drawing.Font("Segoe UI", 10)
$fontLarge = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
$fontMono = New-Object System.Drawing.Font("Consolas", 10)

$form = New-Object System.Windows.Forms.Form
$form.Text = "PasswordForge"
$form.Size = New-Object System.Drawing.Size(1420, 900)
$form.MinimumSize = New-Object System.Drawing.Size(1280, 780)
$form.StartPosition = "CenterScreen"
$form.Font = $fontMain

$menu = New-Object System.Windows.Forms.MenuStrip
$mView = New-Object System.Windows.Forms.ToolStripMenuItem("View")
$mDark = New-Object System.Windows.Forms.ToolStripMenuItem("Dark Mode")
$mDark.CheckOnClick = $true
[void]$mView.DropDownItems.Add($mDark)
[void]$menu.Items.Add($mView)
$form.MainMenuStrip = $menu
$form.Controls.Add($menu)

$main = New-Object System.Windows.Forms.TableLayoutPanel
$main.Dock = 'Fill'
$main.Padding = New-Object System.Windows.Forms.Padding(0, 26, 0, 0)
$main.ColumnCount = 1
$main.RowCount = 2
[void]$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 32)))
$form.Controls.Add($main)

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$tabs.Font = $fontMain
$main.Controls.Add($tabs, 0, 0)

$status = New-Object System.Windows.Forms.StatusStrip
$stText = New-Object System.Windows.Forms.ToolStripStatusLabel
$stText.Text = "Ready"
[void]$status.Items.Add($stText)
$main.Controls.Add($status, 0, 1)

# Rate tab
$tabRate = New-Object System.Windows.Forms.TabPage
$tabRate.Text = "Rate and Improve"
$tabRate.AutoScroll = $true
[void]$tabs.TabPages.Add($tabRate)

$rateLayout = New-Object System.Windows.Forms.TableLayoutPanel
$rateLayout.Dock = 'Fill'
$rateLayout.Padding = New-Object System.Windows.Forms.Padding(14)
$rateLayout.ColumnCount = 2
$rateLayout.RowCount = 1
[void]$rateLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 58)))
[void]$rateLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 42)))
$tabRate.Controls.Add($rateLayout)

$leftRate = New-Object System.Windows.Forms.TableLayoutPanel
$leftRate.Dock = 'Fill'
$leftRate.ColumnCount = 1
$leftRate.RowCount = 7
[void]$leftRate.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 92)))
[void]$leftRate.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 92)))
[void]$leftRate.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 56)))
[void]$leftRate.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 112)))
[void]$leftRate.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 45)))
[void]$leftRate.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 55)))
[void]$leftRate.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 6)))
$rateLayout.Controls.Add($leftRate, 0, 0)

$panelInput = New-Object System.Windows.Forms.TableLayoutPanel
$panelInput.Dock = 'Fill'
$panelInput.ColumnCount = 1
$panelInput.RowCount = 2
[void]$panelInput.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 32)))
[void]$panelInput.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 42)))
$lblPassword = New-Object System.Windows.Forms.Label
$lblPassword.Text = "Type a password to rate it. This tool checks it locally only."
$lblPassword.Dock = 'Fill'
$lblPassword.TextAlign = 'MiddleLeft'
$txtPassword = New-Object System.Windows.Forms.TextBox
$txtPassword.Dock = 'Fill'
$txtPassword.Font = $fontMono
$txtPassword.UseSystemPasswordChar = $true
$txtPassword.Margin = New-Object System.Windows.Forms.Padding(0, 4, 0, 8)
$panelInput.Controls.Add($lblPassword, 0, 0)
$panelInput.Controls.Add($txtPassword, 0, 1)
$leftRate.Controls.Add($panelInput, 0, 0)

$panelScore = New-Object System.Windows.Forms.TableLayoutPanel
$panelScore.Dock = 'Fill'
$panelScore.ColumnCount = 3
$panelScore.RowCount = 2
[void]$panelScore.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 170)))
[void]$panelScore.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$panelScore.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 280)))
[void]$panelScore.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 50)))
[void]$panelScore.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 50)))
$lblScoreTitle = New-Object System.Windows.Forms.Label; $lblScoreTitle.Text = "Score"; $lblScoreTitle.Dock = 'Fill'; $lblScoreTitle.TextAlign = 'MiddleLeft'
$lblScore = New-Object System.Windows.Forms.Label; $lblScore.Text = "0 / 100"; $lblScore.Dock = 'Fill'; $lblScore.TextAlign = 'MiddleLeft'; $lblScore.Font = $fontLarge
$progressScore = New-Object System.Windows.Forms.ProgressBar; $progressScore.Dock = 'Fill'; $progressScore.Minimum = 0; $progressScore.Maximum = 100; $progressScore.Margin = New-Object System.Windows.Forms.Padding(0, 12, 12, 12)
$lblRating = New-Object System.Windows.Forms.Label; $lblRating.Text = "Rating: Very Weak"; $lblRating.Dock = 'Fill'; $lblRating.TextAlign = 'MiddleLeft'
$lblEntropy = New-Object System.Windows.Forms.Label; $lblEntropy.Text = "Entropy: 0 bits | Length: 0"; $lblEntropy.Dock = 'Fill'; $lblEntropy.TextAlign = 'MiddleLeft'
$panelScore.Controls.Add($lblScoreTitle, 0, 0)
$panelScore.Controls.Add($progressScore, 1, 0)
$panelScore.Controls.Add($lblRating, 2, 0)
$panelScore.Controls.Add($lblScore, 0, 1)
$panelScore.Controls.Add($lblEntropy, 1, 1)
$panelScore.SetColumnSpan($lblEntropy, 2)
$leftRate.Controls.Add($panelScore, 0, 1)

$buttonRow = New-Object System.Windows.Forms.FlowLayoutPanel
$buttonRow.Dock = 'Fill'
$buttonRow.FlowDirection = 'LeftToRight'
$buttonRow.WrapContents = $false
$buttonRow.AutoScroll = $true
$btnShow = New-Object System.Windows.Forms.Button; $btnShow.Text = "Show"; $btnShow.Width = 110; $btnShow.Height = 34
$btnCopyCurrent = New-Object System.Windows.Forms.Button; $btnCopyCurrent.Text = "Copy current"; $btnCopyCurrent.Width = 145; $btnCopyCurrent.Height = 34
$btnClear = New-Object System.Windows.Forms.Button; $btnClear.Text = "Clear"; $btnClear.Width = 105; $btnClear.Height = 34
$btnQuickRandom = New-Object System.Windows.Forms.Button; $btnQuickRandom.Text = "Generate random strong password"; $btnQuickRandom.Width = 260; $btnQuickRandom.Height = 34
[void]$buttonRow.Controls.AddRange(@($btnShow, $btnCopyCurrent, $btnClear, $btnQuickRandom))
$leftRate.Controls.Add($buttonRow, 0, 2)

$improveOptions = New-Object System.Windows.Forms.GroupBox
$improveOptions.Text = "Strengthen current password"
$improveOptions.Dock = 'Fill'
$improveGrid = New-Object System.Windows.Forms.TableLayoutPanel
$improveGrid.Dock = 'Fill'
$improveGrid.Padding = New-Object System.Windows.Forms.Padding(8)
$improveGrid.ColumnCount = 4
$improveGrid.RowCount = 2
[void]$improveGrid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 150)))
[void]$improveGrid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 120)))
[void]$improveGrid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50)))
[void]$improveGrid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50)))
[void]$improveGrid.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 50)))
[void]$improveGrid.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 50)))
$lblTargetLen = New-Object System.Windows.Forms.Label; $lblTargetLen.Text = "Target length:"; $lblTargetLen.Dock = 'Fill'; $lblTargetLen.TextAlign = 'MiddleLeft'
$numTargetLen = New-Object System.Windows.Forms.NumericUpDown; $numTargetLen.Minimum = 12; $numTargetLen.Maximum = 64; $numTargetLen.Value = 20; $numTargetLen.Dock = 'Fill'
$chkReadable = New-Object System.Windows.Forms.CheckBox; $chkReadable.Text = "Keep readable"; $chkReadable.Checked = $true; $chkReadable.Dock = 'Fill'
$btnPreviewImprove = New-Object System.Windows.Forms.Button; $btnPreviewImprove.Text = "Create stronger version"; $btnPreviewImprove.Dock = 'Fill'; $btnPreviewImprove.MinimumSize = New-Object System.Drawing.Size(190, 32)
$btnApplyImprove = New-Object System.Windows.Forms.Button; $btnApplyImprove.Text = "Apply strong changes"; $btnApplyImprove.Dock = 'Fill'; $btnApplyImprove.MinimumSize = New-Object System.Drawing.Size(180, 32)
$btnCopyImproved = New-Object System.Windows.Forms.Button; $btnCopyImproved.Text = "Copy improved"; $btnCopyImproved.Dock = 'Fill'; $btnCopyImproved.MinimumSize = New-Object System.Drawing.Size(160, 32)
$improveGrid.Controls.Add($lblTargetLen, 0, 0)
$improveGrid.Controls.Add($numTargetLen, 1, 0)
$improveGrid.Controls.Add($chkReadable, 2, 0)
$improveGrid.Controls.Add($btnPreviewImprove, 3, 0)
$improveGrid.Controls.Add($btnApplyImprove, 2, 1)
$improveGrid.Controls.Add($btnCopyImproved, 3, 1)
$improveOptions.Controls.Add($improveGrid)
$leftRate.Controls.Add($improveOptions, 0, 3)

$grpSuggest = New-Object System.Windows.Forms.GroupBox
$grpSuggest.Text = "Suggestions"
$grpSuggest.Dock = 'Fill'
$txtSuggestions = New-Object System.Windows.Forms.TextBox
$txtSuggestions.Dock = 'Fill'
$txtSuggestions.Multiline = $true
$txtSuggestions.ScrollBars = 'Vertical'
$txtSuggestions.ReadOnly = $true
$txtSuggestions.Font = $fontMain
$grpSuggest.Controls.Add($txtSuggestions)
$leftRate.Controls.Add($grpSuggest, 0, 4)

$grpImproved = New-Object System.Windows.Forms.GroupBox
$grpImproved.Text = "Improved version"
$grpImproved.Dock = 'Fill'
$txtImproved = New-Object System.Windows.Forms.TextBox
$txtImproved.Dock = 'Fill'
$txtImproved.Multiline = $true
$txtImproved.ScrollBars = 'Vertical'
$txtImproved.ReadOnly = $true
$txtImproved.Font = $fontMono
$grpImproved.Controls.Add($txtImproved)
$leftRate.Controls.Add($grpImproved, 0, 5)

$rightRate = New-Object System.Windows.Forms.TableLayoutPanel
$rightRate.Dock = 'Fill'
$rightRate.ColumnCount = 1
$rightRate.RowCount = 2
[void]$rightRate.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 56)))
[void]$rightRate.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 44)))
$rateLayout.Controls.Add($rightRate, 1, 0)

$grpChecklist = New-Object System.Windows.Forms.GroupBox
$grpChecklist.Text = "Password policy checklist"
$grpChecklist.Dock = 'Fill'
$listChecks = New-Object System.Windows.Forms.ListView
$listChecks.Dock = 'Fill'
$listChecks.View = 'Details'
$listChecks.FullRowSelect = $true
$listChecks.GridLines = $true
[void]$listChecks.Columns.Add("Requirement", 390)
[void]$listChecks.Columns.Add("Status", 120)
$grpChecklist.Controls.Add($listChecks)
$rightRate.Controls.Add($grpChecklist, 0, 0)

$grpWarnings = New-Object System.Windows.Forms.GroupBox
$grpWarnings.Text = "Pattern warnings"
$grpWarnings.Dock = 'Fill'
$txtWarnings = New-Object System.Windows.Forms.TextBox
$txtWarnings.Dock = 'Fill'
$txtWarnings.Multiline = $true
$txtWarnings.ScrollBars = 'Vertical'
$txtWarnings.ReadOnly = $true
$txtWarnings.Font = $fontMain
$grpWarnings.Controls.Add($txtWarnings)
$rightRate.Controls.Add($grpWarnings, 0, 1)

# Generator tab
$tabGen = New-Object System.Windows.Forms.TabPage
$tabGen.Text = "Generator"
$tabGen.AutoScroll = $true
[void]$tabs.TabPages.Add($tabGen)
$genLayout = New-Object System.Windows.Forms.TableLayoutPanel
$genLayout.Dock = 'Fill'
$genLayout.Padding = New-Object System.Windows.Forms.Padding(14)
$genLayout.ColumnCount = 1
$genLayout.RowCount = 5
[void]$genLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 136)))
[void]$genLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 96)))
[void]$genLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 60)))
[void]$genLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 40)))
[void]$genLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 6)))
$tabGen.Controls.Add($genLayout)

$grpGenOptions = New-Object System.Windows.Forms.GroupBox
$grpGenOptions.Text = "Random strong password generator"
$grpGenOptions.Dock = 'Fill'
$genOptions = New-Object System.Windows.Forms.TableLayoutPanel
$genOptions.Dock = 'Fill'
$genOptions.Padding = New-Object System.Windows.Forms.Padding(8)
$genOptions.ColumnCount = 6
$genOptions.RowCount = 2
for ($i = 0; $i -lt 6; $i++) { [void]$genOptions.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 16.66))) }
[void]$genOptions.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 50)))
[void]$genOptions.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 50)))
$lblGenLen = New-Object System.Windows.Forms.Label; $lblGenLen.Text = "Length:"; $lblGenLen.Dock = 'Fill'; $lblGenLen.TextAlign = 'MiddleLeft'
$numGenLen = New-Object System.Windows.Forms.NumericUpDown; $numGenLen.Minimum = 8; $numGenLen.Maximum = 128; $numGenLen.Value = 20; $numGenLen.Dock = 'Fill'
$chkUpper = New-Object System.Windows.Forms.CheckBox; $chkUpper.Text = "Uppercase"; $chkUpper.Checked = $true; $chkUpper.Dock = 'Fill'
$chkLower = New-Object System.Windows.Forms.CheckBox; $chkLower.Text = "Lowercase"; $chkLower.Checked = $true; $chkLower.Dock = 'Fill'
$chkNumbers = New-Object System.Windows.Forms.CheckBox; $chkNumbers.Text = "Numbers"; $chkNumbers.Checked = $true; $chkNumbers.Dock = 'Fill'
$chkSymbols = New-Object System.Windows.Forms.CheckBox; $chkSymbols.Text = "Symbols"; $chkSymbols.Checked = $true; $chkSymbols.Dock = 'Fill'
$chkSimilar = New-Object System.Windows.Forms.CheckBox; $chkSimilar.Text = "Exclude similar characters"; $chkSimilar.Checked = $true; $chkSimilar.Dock = 'Fill'
$btnGenerateOne = New-Object System.Windows.Forms.Button; $btnGenerateOne.Text = "Generate random strong password"; $btnGenerateOne.Dock = 'Fill'
$btnGenerateTen = New-Object System.Windows.Forms.Button; $btnGenerateTen.Text = "Generate 10 strong passwords"; $btnGenerateTen.Dock = 'Fill'
$btnCopySelected = New-Object System.Windows.Forms.Button; $btnCopySelected.Text = "Copy selected or first"; $btnCopySelected.Dock = 'Fill'
$genOptions.Controls.Add($lblGenLen, 0, 0)
$genOptions.Controls.Add($numGenLen, 1, 0)
$genOptions.Controls.Add($chkUpper, 2, 0)
$genOptions.Controls.Add($chkLower, 3, 0)
$genOptions.Controls.Add($chkNumbers, 4, 0)
$genOptions.Controls.Add($chkSymbols, 5, 0)
$genOptions.Controls.Add($chkSimilar, 0, 1)
$genOptions.Controls.Add($btnGenerateOne, 2, 1)
$genOptions.SetColumnSpan($btnGenerateOne, 2)
$genOptions.Controls.Add($btnGenerateTen, 4, 1)
$genOptions.Controls.Add($btnCopySelected, 5, 1)
$grpGenOptions.Controls.Add($genOptions)
$genLayout.Controls.Add($grpGenOptions, 0, 0)

$grpPhrase = New-Object System.Windows.Forms.GroupBox
$grpPhrase.Text = "Passphrase generator"
$grpPhrase.Dock = 'Fill'
$phraseOptions = New-Object System.Windows.Forms.TableLayoutPanel
$phraseOptions.Dock = 'Fill'
$phraseOptions.Padding = New-Object System.Windows.Forms.Padding(8)
$phraseOptions.ColumnCount = 7
$phraseOptions.RowCount = 1
for ($i = 0; $i -lt 7; $i++) { [void]$phraseOptions.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 14.28))) }
$lblWords = New-Object System.Windows.Forms.Label; $lblWords.Text = "Words:"; $lblWords.Dock = 'Fill'; $lblWords.TextAlign = 'MiddleLeft'
$numWords = New-Object System.Windows.Forms.NumericUpDown; $numWords.Minimum = 3; $numWords.Maximum = 8; $numWords.Value = 4; $numWords.Dock = 'Fill'
$lblDelim = New-Object System.Windows.Forms.Label; $lblDelim.Text = "Delimiter:"; $lblDelim.Dock = 'Fill'; $lblDelim.TextAlign = 'MiddleLeft'
$txtDelim = New-Object System.Windows.Forms.TextBox; $txtDelim.Text = "-"; $txtDelim.Dock = 'Fill'
$chkPhraseNum = New-Object System.Windows.Forms.CheckBox; $chkPhraseNum.Text = "Add number"; $chkPhraseNum.Checked = $true; $chkPhraseNum.Dock = 'Fill'
$chkPhraseSym = New-Object System.Windows.Forms.CheckBox; $chkPhraseSym.Text = "Add symbol"; $chkPhraseSym.Checked = $true; $chkPhraseSym.Dock = 'Fill'
$btnPhrase = New-Object System.Windows.Forms.Button; $btnPhrase.Text = "Generate passphrase"; $btnPhrase.Dock = 'Fill'
$phraseOptions.Controls.Add($lblWords, 0, 0)
$phraseOptions.Controls.Add($numWords, 1, 0)
$phraseOptions.Controls.Add($lblDelim, 2, 0)
$phraseOptions.Controls.Add($txtDelim, 3, 0)
$phraseOptions.Controls.Add($chkPhraseNum, 4, 0)
$phraseOptions.Controls.Add($chkPhraseSym, 5, 0)
$phraseOptions.Controls.Add($btnPhrase, 6, 0)
$grpPhrase.Controls.Add($phraseOptions)
$genLayout.Controls.Add($grpPhrase, 0, 1)

$grpGenOut = New-Object System.Windows.Forms.GroupBox
$grpGenOut.Text = "Generated passwords"
$grpGenOut.Dock = 'Fill'
$txtGenerated = New-Object System.Windows.Forms.TextBox
$txtGenerated.Dock = 'Fill'
$txtGenerated.Multiline = $true
$txtGenerated.ScrollBars = 'Both'
$txtGenerated.WordWrap = $false
$txtGenerated.ReadOnly = $true
$txtGenerated.Font = $fontMono
$grpGenOut.Controls.Add($txtGenerated)
$genLayout.Controls.Add($grpGenOut, 0, 2)

$grpGenAnalysis = New-Object System.Windows.Forms.GroupBox
$grpGenAnalysis.Text = "Selected or generated password analysis"
$grpGenAnalysis.Dock = 'Fill'
$txtGenAnalysis = New-Object System.Windows.Forms.TextBox
$txtGenAnalysis.Dock = 'Fill'
$txtGenAnalysis.Multiline = $true
$txtGenAnalysis.ScrollBars = 'Vertical'
$txtGenAnalysis.ReadOnly = $true
$txtGenAnalysis.Font = $fontMain
$grpGenAnalysis.Controls.Add($txtGenAnalysis)
$genLayout.Controls.Add($grpGenAnalysis, 0, 3)

# Notes tab
$tabAbout = New-Object System.Windows.Forms.TabPage
$tabAbout.Text = "Notes"
[void]$tabs.TabPages.Add($tabAbout)
$txtAbout = New-Object System.Windows.Forms.TextBox
$txtAbout.Dock = 'Fill'
$txtAbout.Multiline = $true
$txtAbout.ReadOnly = $true
$txtAbout.ScrollBars = 'Vertical'
$txtAbout.Font = $fontMain
$txtAbout.Text = @"

What this app does:
- Rates password strength locally.
- Suggests practical changes.
- Builds a stronger version of the current password.
- Generates random strong passwords.
- Generates readable passphrases.
- Checks common weak patterns.

Important:
- It does not send passwords anywhere.
- It does not save passwords.
- It does not check live breach databases.

"@
$tabAbout.Controls.Add($txtAbout)
#endregion

#region UI Functions
function Update-AnalysisUI {
    $analysis = Get-PasswordAnalysis $txtPassword.Text
    $progressScore.Value = [Math]::Max(0, [Math]::Min(100, $analysis.Score))
    $lblScore.Text = "$($analysis.Score) / 100"
    $lblRating.Text = "Rating: $($analysis.Rating)"
    $lblEntropy.Text = "Entropy: $($analysis.Entropy) bits | Length: $($analysis.Length)"
    $txtSuggestions.Text = ($analysis.Suggestions -join "`r`n")
    $txtWarnings.Text = ($analysis.Warnings -join "`r`n")
    $listChecks.Items.Clear()
    foreach ($check in $analysis.Checks) {
        $item = New-Object System.Windows.Forms.ListViewItem($check.Requirement)
        [void]$item.SubItems.Add($check.Status)
        [void]$listChecks.Items.Add($item)
    }
    $stText.Text = "Score $($analysis.Score), $($analysis.Rating)"
}

function Analyze-GeneratedText {
    $lines = $txtGenerated.Text -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 }
    if ($lines.Count -lt 1) { $txtGenAnalysis.Clear(); return }
    $pw = $lines[0].Trim()
    $analysis = Get-PasswordAnalysis $pw
    $txtGenAnalysis.Text = "Password: $pw`r`nScore: $($analysis.Score) / 100`r`nRating: $($analysis.Rating)`r`nEntropy: $($analysis.Entropy) bits`r`nLength: $($analysis.Length)`r`n`r`nSuggestions:`r`n" + ($analysis.Suggestions -join "`r`n")
}

function Set-DarkMode {
    param([bool]$On)
    $bg = [System.Drawing.SystemColors]::Control
    $fg = [System.Drawing.SystemColors]::ControlText
    $boxBg = [System.Drawing.SystemColors]::Window
    $boxFg = [System.Drawing.SystemColors]::WindowText
    if ($On) {
        $bg = [System.Drawing.Color]::FromArgb(18, 18, 18)
        $fg = [System.Drawing.Color]::Gainsboro
        $boxBg = [System.Drawing.Color]::FromArgb(28, 28, 28)
        $boxFg = [System.Drawing.Color]::White
    }
    $stack = New-Object System.Collections.Stack
    $stack.Push($form)
    while ($stack.Count -gt 0) {
        $c = $stack.Pop()
        foreach ($child in $c.Controls) { $stack.Push($child) }
        try {
            if ($c -is [System.Windows.Forms.TextBox] -or $c -is [System.Windows.Forms.ListView] -or $c -is [System.Windows.Forms.NumericUpDown]) {
                $c.BackColor = $boxBg
                $c.ForeColor = $boxFg
            } else {
                $c.BackColor = $bg
                $c.ForeColor = $fg
            }
            if ($c -is [System.Windows.Forms.Button]) {
                if ($On) { $c.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat } else { $c.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard }
            }
        } catch {}
    }
    foreach ($page in $tabs.TabPages) {
        $page.BackColor = $bg
        $page.ForeColor = $fg
    }
}
#endregion

#region Events
$txtPassword.Add_TextChanged({ Update-AnalysisUI })
$btnShow.Add_Click({
    $txtPassword.UseSystemPasswordChar = -not $txtPassword.UseSystemPasswordChar
    if ($txtPassword.UseSystemPasswordChar) { $btnShow.Text = "Show" } else { $btnShow.Text = "Hide" }
})
$btnCopyCurrent.Add_Click({
    if ($txtPassword.Text.Length -gt 0) {
        [System.Windows.Forms.Clipboard]::SetText($txtPassword.Text)
        $stText.Text = "Copied current password"
    }
})
$btnClear.Add_Click({
    $txtPassword.Clear()
    $txtImproved.Clear()
    $stText.Text = "Cleared"
})
$btnQuickRandom.Add_Click({
    $pw = New-StrongPassword -Length 20 -UseUpper $true -UseLower $true -UseNumbers $true -UseSymbols $true -ExcludeSimilar $true
    $txtPassword.Text = $pw
    $txtImproved.Text = $pw
    $stText.Text = "Generated random strong password"
})
$btnPreviewImprove.Add_Click({
    $txtImproved.Text = Strengthen-Password -Password $txtPassword.Text -TargetLength ([int]$numTargetLen.Value) -Readable $chkReadable.Checked
    $stText.Text = "Created stronger version"
})
$btnApplyImprove.Add_Click({
    $txtPassword.Text = Strengthen-Password -Password $txtPassword.Text -TargetLength ([int]$numTargetLen.Value) -Readable $chkReadable.Checked
    $txtImproved.Text = $txtPassword.Text
    $stText.Text = "Applied strong changes"
})
$btnCopyImproved.Add_Click({
    if ($txtImproved.Text.Length -gt 0) {
        [System.Windows.Forms.Clipboard]::SetText($txtImproved.Text)
        $stText.Text = "Copied improved password"
    }
})

$btnGenerateOne.Add_Click({
    $pw = New-StrongPassword -Length ([int]$numGenLen.Value) -UseUpper $chkUpper.Checked -UseLower $chkLower.Checked -UseNumbers $chkNumbers.Checked -UseSymbols $chkSymbols.Checked -ExcludeSimilar $chkSimilar.Checked
    $txtGenerated.Text = $pw
    Analyze-GeneratedText
    $stText.Text = "Generated one strong password"
})
$btnGenerateTen.Add_Click({
    $list = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt 10; $i++) {
        [void]$list.Add((New-StrongPassword -Length ([int]$numGenLen.Value) -UseUpper $chkUpper.Checked -UseLower $chkLower.Checked -UseNumbers $chkNumbers.Checked -UseSymbols $chkSymbols.Checked -ExcludeSimilar $chkSimilar.Checked))
    }
    $txtGenerated.Text = ($list.ToArray() -join "`r`n")
    Analyze-GeneratedText
    $stText.Text = "Generated 10 strong passwords"
})
$btnCopySelected.Add_Click({
    $text = $txtGenerated.SelectedText
    if ([string]::IsNullOrWhiteSpace($text)) {
        $lines = $txtGenerated.Text -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 }
        if ($lines.Count -gt 0) { $text = $lines[0].Trim() }
    }
    if (-not [string]::IsNullOrWhiteSpace($text)) {
        [System.Windows.Forms.Clipboard]::SetText($text)
        $stText.Text = "Copied generated password"
    }
})
$btnPhrase.Add_Click({
    $delim = $txtDelim.Text
    if ([string]::IsNullOrEmpty($delim)) { $delim = "-" }
    $pw = New-Passphrase -Words ([int]$numWords.Value) -Delimiter $delim -AddNumber $chkPhraseNum.Checked -AddSymbol $chkPhraseSym.Checked
    $txtGenerated.Text = $pw
    Analyze-GeneratedText
    $stText.Text = "Generated passphrase"
})
$mDark.Add_CheckedChanged({ Set-DarkMode $mDark.Checked })
#endregion

Update-AnalysisUI
[void]$form.ShowDialog()
