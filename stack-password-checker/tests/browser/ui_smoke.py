"""Optional browser smoke test (not run by unittest). Needs: pip install playwright && playwright install chromium
Start the app first (python run.py), then:  python tests/browser/ui_smoke.py [http://127.0.0.1:5000/]"""
import sys
from playwright.sync_api import sync_playwright
B = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000/"
res=[]
import time
def wait_val(pg,sel,pred,t=20):
    end=time.time()+t
    while time.time()<end:
        if pred(pg.input_value(sel)): return
        pg.wait_for_timeout(200)
    raise TimeoutError(sel)
def ok(name,cond,extra=""): res.append((name,bool(cond))); print(("PASS " if cond else "FAIL ")+name, extra)
with sync_playwright() as p:
    br=p.chromium.launch()
    errs=[]
    # ---- desktop 1440 and 1200 (nav visible), no horizontal scroll
    for w in (1440,1200):
        pg=br.new_page(viewport={"width":w,"height":900}); pg.on("console",lambda m: errs.append(m.text) if m.type=="error" else None); pg.on("pageerror",lambda e: errs.append(str(e)))
        pg.goto(B); pg.wait_for_selector("nav.links a")
        labels=pg.eval_on_selector_all("nav.links a","e=>e.map(x=>x.textContent)")
        ok(f"desktop {w}: 9 nav links", len(labels)==9, labels)
        ok(f"desktop {w}: no horizontal scroll", pg.evaluate("document.documentElement.scrollWidth<=innerWidth"))
        navbox=pg.evaluate("(()=>{const l=document.querySelector('nav.links').getBoundingClientRect();const t=document.getElementById('themeBtn').getBoundingClientRect();return l.right<=t.left+1&&l.height<60})()")
        ok(f"desktop {w}: nav links fit on one row", navbox)
        pg.close()
    # ---- anchors
    pg=br.new_page(viewport={"width":1440,"height":900}); pg.goto(B)
    for lab,sel in (("Dashboard","#toolkit"),("History","#history"),("About Security","#about")):
        pg.click(f"nav.links >> text='{lab}'"); pg.wait_for_timeout(1500)
        ok(f"anchor {lab} -> {sel}", pg.evaluate(f"(()=>{{const r=document.querySelector('{sel}').getBoundingClientRect();return r.top<innerHeight&&r.bottom>0}})()"))
    # every nav target page loads
    for href in ("text-crypto.html","hash.html","file-hash.html","file-crypto.html","verify.html"):
        r=pg.goto(B+href); ok(f"page {href}", r.status==200 and pg.locator("nav.links a").count()==9)
    # ---- mobile 390
    m=br.new_page(viewport={"width":390,"height":800},is_mobile=True,has_touch=True); m.goto(B)
    ok("mobile: no horizontal scroll", m.evaluate("document.documentElement.scrollWidth<=innerWidth"))
    m.click("#burger"); ok("mobile: menu opens with 9 links", m.locator("#mpanel a").count()==9 and m.is_visible("#mpanel"))
    m.click("#mpanel >> text='History'"); m.wait_for_timeout(400); ok("mobile: menu closes after tap", not m.is_visible("#mpanel"))
    for href in ("text-crypto.html","hash.html","file-hash.html","file-crypto.html","verify.html"):
        m.goto(B+href); ok(f"mobile {href} no h-scroll", m.evaluate("document.documentElement.scrollWidth<=innerWidth"))
    # ---- functional: text encrypt/decrypt, hash
    pg.goto(B+"text-crypto.html")
    pg.fill("#encIn","hello"); pg.fill("#encPw","Correct-Horse-9!"); pg.fill("#encPw2","Correct-Horse-9!"); pg.click("#encBtn")
    wait_val(pg,"#encOut",lambda v: len(v)>20)
    ct=pg.input_value("#encOut"); ok("text encrypt produces output without plaintext", "hello" not in ct and len(ct)>40)
    pg.click("#tabDec"); pg.fill("#decIn",ct); pg.fill("#decPw","Correct-Horse-9!"); pg.click("#decBtn")
    wait_val(pg,"#decOut",lambda v: len(v)>0)
    ok("text decrypt returns 'hello'", pg.input_value("#decOut")=="hello")
    pg.click("#decClear"); pg.fill("#decIn",ct); pg.fill("#decPw","wrong-password-1"); pg.click("#decBtn"); pg.wait_for_timeout(3000)
    ok("wrong password gives no plaintext", pg.input_value("#decOut")=="")
    pg.goto(B+"hash.html"); pg.fill("#hIn","hello"); pg.click("#hGo"); pg.wait_for_timeout(800)
    ok("SHA-256('hello') shown", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" in pg.inner_text("body"))
    # ---- password checker + history persists across reload
    pg.goto(B); pg.wait_for_timeout(2500); pg.fill("#pw","Tr0ub4dor&3-Xylophone!"); pg.click("#analyze"); pg.wait_for_timeout(1200)
    n1=pg.locator("#histList li").count(); pg.reload(); pg.wait_for_timeout(1200)
    ok("history saved and survives reload", n1>=1 and pg.locator("#histList li").count()==n1, n1)
    # ---- offline: tools still work (local only)
    ctx=br.new_context(); op=ctx.new_page(); op.goto(B+"hash.html"); op.wait_for_selector("#hGo"); ctx.set_offline(True)
    op.fill("#hIn","hello"); op.click("#hGo"); op.wait_for_timeout(800)
    ok("offline: hashing still works", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" in op.inner_text("body"))
    ok("no console/page errors", not [e for e in errs if "fonts.g" not in e and "ERR_" not in e], errs[:3])
    br.close()
print("\n%d/%d passed"%(sum(1 for _,c in res if c),len(res)))
