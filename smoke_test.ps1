$ErrorActionPreference = 'Stop'
$base = 'http://127.0.0.1:8011'
$dbFile = Join-Path $env:TEMP 'aba_pos_smoke.db'
Remove-Item $dbFile -ErrorAction SilentlyContinue
$dbUrl = 'sqlite:///' + ($dbFile -replace '\\', '/')
# Throwaway database => throwaway administrator. POS_ADMIN_PASSWORD is supplied
# through the job below, so the API never generates (or writes out) a password.
$adminUser = if ($env:POS_ADMIN_USERNAME) { $env:POS_ADMIN_USERNAME } else { 'admin' }
$adminPass = 'SmokeAdminPass123'
Write-Output "DB: $dbUrl"

$job = Start-Job -ScriptBlock {
  param($url, $user, $pass)
  $env:DATABASE_URL = $url
  $env:POS_ADMIN_USERNAME = $user
  $env:POS_ADMIN_PASSWORD = $pass
  Set-Location 'd:\ABA payment project\backend_api'
  python -m uvicorn main:app --port 8011 --log-level warning
} -ArgumentList $dbUrl, $adminUser, $adminPass

function Wait-Api {
  for ($i = 0; $i -lt 40; $i++) {
    try { return Invoke-RestMethod "$base/api/health" -TimeoutSec 2 } catch { Start-Sleep -Milliseconds 750 }
  }
  throw 'backend did not start'
}
function Get-Status($block) {
  try { return @{ ok = $true; body = & $block } }
  catch {
    $code = $null
    if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    return @{ ok = $false; status = $code; body = $_.ErrorDetails.Message }
  }
}

try {
  $health = Wait-Api
  Write-Output "1) health      : $($health | ConvertTo-Json -Compress)"

  # Every /api route needs a sign-in now; the temp database bootstraps the
  # administrator from POS_ADMIN_PASSWORD (see the job above).
  $login = Invoke-RestMethod "$base/api/auth/login" -Method Post -ContentType 'application/json' `
    -Body (@{ username = $adminUser; password = $adminPass } | ConvertTo-Json)
  $hdr = @{ Authorization = "Bearer $($login.token)" }
  Write-Output "2) sign in     : $($login.user.username)/$($login.user.role) token=$($login.token.Substring(0,8))..."

  $stats = Invoke-RestMethod "$base/api/stats/summary" -Headers $hdr
  Write-Output "3) stats init  : products=$($stats.products) categories=$($stats.categories) orders=$($stats.orders_today)"

  $cat = Invoke-RestMethod "$base/api/categories" -Headers $hdr -Method Post -ContentType 'application/json' `
    -Body (@{ name = 'Smoke Drinks'; color = '#2f5ff5' } | ConvertTo-Json)
  Write-Output "4) category    : id=$($cat.id) name=$($cat.name)"

  $prod = Invoke-RestMethod "$base/api/products" -Headers $hdr -Method Post -ContentType 'application/json' `
    -Body (@{ title = 'Smoke Coke'; price = 1.5; discount = 10; stock = 10; category_id = $cat.id } | ConvertTo-Json)
  Write-Output "5) product     : id=$($prod.id) price=$($prod.price) final=$($prod.final_price) stock=$($prod.stock)"

  $cash = Invoke-RestMethod "$base/api/orders" -Headers $hdr -Method Post -ContentType 'application/json' `
    -Body (@{ payment_method = 'CASH'; amount_paid = 5; items = @(@{ product_id = $prod.id; quantity = 2 }) } | ConvertTo-Json -Depth 5)
  Write-Output "6) cash order  : $($cash.order.order_number) status=$($cash.order.status) total=$($cash.order.total) paid=$($cash.order.amount_paid) change=$($cash.order.change_amount)"

  $afterCash = Invoke-RestMethod "$base/api/products/$($prod.id)" -Headers $hdr
  Write-Output "7) stock after : $($afterCash.stock) (expect 8)"

  $khqr = Get-Status { Invoke-RestMethod "$base/api/orders" -Headers $hdr -Method Post -ContentType 'application/json' `
    -Body (@{ payment_method = 'KHQR'; items = @(@{ product_id = $prod.id; quantity = 1 }) } | ConvertTo-Json -Depth 5) }
  if ($khqr.ok) {
    Write-Output "8) khqr order  : $($khqr.body.order.order_number) status=$($khqr.body.order.status) gateway_ok=$($khqr.body.gateway_ok) msg=$($khqr.body.gateway_message)"
    $khqrId = $khqr.body.order.id
  } else {
    Write-Output "9) khqr order  : HTTP $($khqr.status) $($khqr.body)"
  }

  $manual = Get-Status { Invoke-RestMethod "$base/api/orders/$($cash.order.id)/mark-paid" -Headers $hdr -Method Post }
  Write-Output "10) mark-paid   : ok=$($manual.ok) status=$($manual.body.status)"

  $list = Invoke-RestMethod "$base/api/orders?limit=5" -Headers $hdr
  Write-Output "11) orders list : $($list.Count) row(s) | first=$($list[0].order_number) items=$($list[0].item_count)"

  $detail = Invoke-RestMethod "$base/api/orders/$($cash.order.id)" -Headers $hdr
  Write-Output "12) order items: $($detail.items.Count) line(s) line_total=$($detail.items[0].line_total) subtotal=$($detail.subtotal) discount=$($detail.discount_total)"

  $settings = Invoke-RestMethod "$base/api/settings" -Headers $hdr
  Write-Output "13) settings   : merchant=$($settings.settings.merchant_name) currency=$($settings.settings.currency) locked=$($settings.locked_keys -join ',') webhook=$($settings.webhook_url)"

  $saved = Invoke-RestMethod "$base/api/settings" -Headers $hdr -Method Put -ContentType 'application/json' `
    -Body (@{ merchant_name = 'Smoke Store'; demo_mode = $true } | ConvertTo-Json)
  Write-Output "14) save       : merchant=$($saved.settings.merchant_name) demo=$($saved.settings.demo_mode)"

  $urls = Invoke-RestMethod "$base/api/settings/aba-urls" -Headers $hdr
  Write-Output "15) aba urls   : $($urls | ConvertTo-Json -Compress -Depth 4)".Substring(0, [Math]::Min(300, "$($urls | ConvertTo-Json -Compress -Depth 4)".Length))

  $backup = Invoke-RestMethod "$base/api/data/backup" -Headers $hdr
  Write-Output "16) backup     : app=$($backup.app) v=$($backup.version) counts=$($backup.counts | ConvertTo-Json -Compress) orders=$($backup.orders.Count)"

  $imported = Invoke-RestMethod "$base/api/data/import" -Headers $hdr -Method Post -ContentType 'application/json' `
    -Body (@{ mode = 'merge'; data = $backup } | ConvertTo-Json -Depth 10)
  Write-Output "17) import mg  : ok=$($imported.ok) stats=$($imported.stats | ConvertTo-Json -Compress)"

  $badReset = Get-Status { Invoke-RestMethod "$base/api/data/reset?confirm=NOPE" -Headers $hdr -Method Post }
  Write-Output "18) reset bad  : ok=$($badReset.ok) status=$($badReset.status) body=$($badReset.body)"

  $logs = Invoke-RestMethod "$base/api/webhook/logs?limit=5" -Headers $hdr
  Write-Output "19) webhook lg : $($logs.Count) entr(ies)"

  $goodReset = Invoke-RestMethod "$base/api/data/reset?confirm=RESET" -Headers $hdr -Method Post
  Write-Output "20) reset ok   : ok=$($goodReset.ok) detail=$($goodReset.detail)"

  $final = Invoke-RestMethod "$base/api/stats/summary" -Headers $hdr
  Write-Output "21) stats final: products=$($final.products) categories=$($final.categories) orders_today=$($final.orders_today) pending=$($final.pending_orders)"

  $kept = Invoke-RestMethod "$base/api/settings" -Headers $hdr
  Write-Output "22) settings kept after reset: merchant=$($kept.settings.merchant_name)"
}
finally {
  Stop-Job $job -ErrorAction SilentlyContinue
  Receive-Job $job -ErrorAction SilentlyContinue | Select-Object -Last 15 | ForEach-Object { "uvicorn> $_" }
  Remove-Job $job -Force -ErrorAction SilentlyContinue
  Remove-Item $dbFile -ErrorAction SilentlyContinue
  Write-Output 'smoke test finished'
}
