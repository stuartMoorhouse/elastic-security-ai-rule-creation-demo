$ErrorActionPreference = "Stop"

# Create the jsmith local account used in the Okta credential stuffing demo.
# The remediation runscript disables this account when the detection rule fires.

function New-PolicySafePassword {
    # Cryptographically random password: 6 upper + 6 lower + 4 digit + 4 special = 20 chars.
    # Uses only unambiguous chars; contains no username substring or dictionary words.
    $upper   = "ABCDEFGHJKLMNPQRSTUVWXY"
    $lower   = "abcdefghjkmnpqrstuvwxyz"
    $digits  = "23456789"
    $special = "@!#%"
    $rng     = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $b       = New-Object byte[] 64
    $rng.GetBytes($b)

    $chars = @()
    for ($i = 0;  $i -lt 6;  $i++) { $chars += $upper[$b[$i]    % $upper.Length] }
    for ($i = 6;  $i -lt 12; $i++) { $chars += $lower[$b[$i]    % $lower.Length] }
    for ($i = 12; $i -lt 16; $i++) { $chars += $digits[$b[$i]   % $digits.Length] }
    for ($i = 16; $i -lt 20; $i++) { $chars += $special[$b[$i]  % $special.Length] }

    # Fisher-Yates shuffle using remaining random bytes
    for ($i = 19; $i -gt 0; $i--) {
        $j = $b[20 + $i] % ($i + 1)
        $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
    }
    return -join $chars
}

if (-not (Get-LocalUser -Name "jsmith" -ErrorAction SilentlyContinue)) {
    $plain  = New-PolicySafePassword
    $secPwd = ConvertTo-SecureString $plain -AsPlainText -Force
    try {
        New-LocalUser `
            -Name                "jsmith" `
            -Password            $secPwd `
            -FullName            "John Smith" `
            -Description         "Demo user - Okta credential stuffing scenario" `
            -PasswordNeverExpires `
            -ErrorAction         Stop
        Add-LocalGroupMember -Group "Users" -Member "jsmith" -ErrorAction SilentlyContinue
        Write-Output "Created local account 'jsmith'."
    } catch {
        Write-Warning "New-LocalUser failed: $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-Output "Local account 'jsmith' already exists - skipping creation."
}

exit 0
