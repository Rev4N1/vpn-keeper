# uia-dump.ps1 - describe the Connect Tunnel windows (control names, ids, types).
# Read-only. Password boxes are never read. Each run appends to uia-dump.txt
# in your profile folder, so run it once per window you want captured.
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$out = "$env:USERPROFILE\uia-dump.txt"
"`n=== session $([Diagnostics.Process]::GetCurrentProcess().SessionId) $(Get-Date -Format s)" | Out-File $out -Append -Encoding utf8
$root = [Windows.Automation.AutomationElement]::RootElement
$pids = @(Get-Process SnwlConnect -ErrorAction SilentlyContinue | ForEach-Object Id)
"SnwlConnect pids: $pids" | Out-File $out -Append -Encoding utf8

function Walk($el, $depth) {
    if ($depth -gt 8) { return }
    $c = $el.Current
    $val = ''
    if (-not $c.IsPassword) {
        try { $val = ' value="' + $el.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern).Current.Value + '"' } catch {}
    }
    $pats = ($el.GetSupportedPatterns() | ForEach-Object { $_.ProgrammaticName -replace 'PatternIdentifiers.Pattern', '' }) -join ','
    $type = $c.ControlType.ProgrammaticName -replace 'ControlType.', ''
    ('  ' * $depth) + "[$type] name=""$($c.Name)"" id=""$($c.AutomationId)"" class=""$($c.ClassName)"" enabled=$($c.IsEnabled) pwd=$($c.IsPassword) {$pats}$val" |
        Out-File $out -Append -Encoding utf8
    $w = [Windows.Automation.TreeWalker]::ControlViewWalker
    $ch = $w.GetFirstChild($el)
    while ($ch) { Walk $ch ($depth + 1); $ch = $w.GetNextSibling($ch) }
}

foreach ($p in $pids) {
    $cond = New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ProcessIdProperty, $p)
    foreach ($w in $root.FindAll([Windows.Automation.TreeScope]::Children, $cond)) { Walk $w 0 }
}
"done" | Out-File $out -Append -Encoding utf8
Write-Host "Saved to $out"
