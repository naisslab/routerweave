// The host supplies the browser and tab handles. Python schedules the actions.
import fs from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';

export function matchesRegisteredEntry(actual, expected, ignoredQueryKeys=[]) {
  const a=new URL(actual),e=new URL(expected);
  for(const key of ignoredQueryKeys){a.searchParams.delete(key);e.searchParams.delete(key);}
  return a.href===e.href;
}

export async function readTabFocus(browser, tab) {
  if (tab.capabilities && (await tab.capabilities.list()).some(c => c.id === 'cdp')) {
    const cdp = await tab.capabilities.get('cdp');
    const reply = await cdp.send('Runtime.evaluate', {
      expression: "({focused:document.hasFocus(),visible:document.visibilityState==='visible'})",
      returnByValue: true,
    });
    const value = reply.result?.value;
    if (reply.exceptionDetails || typeof value?.focused !== 'boolean' || typeof value?.visible !== 'boolean')
      throw new Error('Pinned tab has no reliable document focus evidence');
    return {...value, source: 'document_focus'};
  }
  return {focused: (await browser.tabs.selected())?.id === tab.id, source: 'browser_selection'};
}

export async function readDecodedFrames(tab, selector) {
  const cdp = await tab.capabilities.get('cdp');
  const reply = await cdp.send('Runtime.evaluate', {returnByValue:true, expression:
    `(()=>{const rows=[...document.querySelectorAll(${JSON.stringify(selector)})];
      if(rows.length!==1)return {count:rows.length,frames:null};
      const v=rows[0],q=typeof v.getVideoPlaybackQuality==='function'?v.getVideoPlaybackQuality():null;
      return {count:1,frames:q?.totalVideoFrames??v.webkitDecodedFrameCount??null};})()`});
  const value=reply.result?.value;
  if(reply.exceptionDetails || !value || value.count>1)
    throw new Error('Decoded-frame observation has no unambiguous media element');
  return value.count===1 && Number.isInteger(value.frames) && value.frames>=0 ? value.frames : null;
}

export async function revealScrolledControl(tab, selector, direction, checkRequest=()=>{}) {
  if (!['scroll_up','scroll_down'].includes(direction)) throw new Error('Unsupported scroll reveal');
  for (let attempt=0;attempt<=3;attempt++) {
    checkRequest();
    const visible=await tab.playwright.locator(selector).evaluateAll(es=>es.some(e=>{
      const r=e.getBoundingClientRect();
      const left=Math.max(0,r.left),right=Math.min(innerWidth,r.right);
      const top=Math.max(0,r.top),bottom=Math.min(innerHeight,r.bottom);
      return right>left&&bottom>top&&e.contains(document.elementFromPoint((left+right)/2,(top+bottom)/2));
    }));
    if (visible) return;
    if (attempt===3) throw new Error('Registered control remained outside viewport after bounded reveal');
    const viewport=await tab.playwright.evaluate(()=>({width:innerWidth,height:innerHeight}));
    const cdp=await tab.capabilities.get('cdp');
    checkRequest();
    await cdp.send('Input.dispatchMouseEvent',{type:'mouseWheel',x:viewport.width*.8,
      y:viewport.height*.5,deltaX:0,deltaY:viewport.height*.8*(direction==='scroll_up'?-1:1)});
  }
}

export async function revealMediaViewport(tab, selector, checkRequest=()=>{}) {
  for(let attempt=0;attempt<4;attempt++) {
    checkRequest();
    const rows=await tab.playwright.locator(selector).evaluateAll(es=>es.map(e=>{
      const r=e.getBoundingClientRect();
      return {x:r.x,y:r.y,width:r.width,height:r.height,bottom:r.bottom,
        viewportWidth:innerWidth,viewportHeight:innerHeight,
        visible:getComputedStyle(e).visibility!=='hidden'};
    }).filter(r=>r.visible&&r.width>0&&r.height>0));
    if(!rows.length)return;
    if(rows.length!==1)throw new Error('Media reveal requires one unambiguous player');
    const r=rows[0],h=r.viewportHeight;
    if(r.y>=80&&(r.bottom<=h-20||(r.height>h-100&&r.y<=100)))return;
    if(attempt===3)throw new Error('Player remains outside viewport after bounded scroll');
    const deltaY=Math.max(-h*.8,Math.min(h*.8,r.y-100));
    if(Math.abs(deltaY)<1)throw new Error('Player cannot fit the available viewport');
    const cdp=await tab.capabilities.get('cdp');
    checkRequest();
    await cdp.send('Input.dispatchMouseEvent',{type:'mouseWheel',x:r.viewportWidth*.8,
      y:h*.6,deltaX:0,deltaY});
    await new Promise(resolve=>setTimeout(resolve,350));
  }
}

// Animated media bars can report visible while their click point hits the
// page underneath. Reveal the registered surface, then require stable geometry
// and an independent hit test before one click. Never retry an uncertain click.
export async function clickRevealedControl(tab, control, checkRequest=()=>{}) {
  const cdp = await tab.capabilities.get('cdp');
  let hover;
  for(let attempt=0;attempt<5;attempt++) {
    hover = await tab.playwright.locator(control.reveal_hover_selector).evaluate(e=>{
    const r=e.getBoundingClientRect();
    const left=Math.max(0,r.left),right=Math.min(innerWidth,r.right);
    const top=Math.max(0,r.top),bottom=Math.min(innerHeight,r.bottom);
    if(r.width<=0||r.height<=0)return null;
    return right>left && bottom>top ? {x:(left+right)/2,y:(top+bottom)/2}:
      {x:innerWidth/2,y:innerHeight/2,deltaY:Math.sign(r.top)*Math.round(innerHeight*.72)};
    });
    if(!hover||hover.deltaY===undefined)break;
    if(attempt===4)throw new Error('Registered reveal surface is outside the viewport');
    checkRequest();
    await cdp.send('Input.dispatchMouseEvent',{type:'mouseWheel',deltaX:0,...hover});
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  if (!hover) throw new Error('Registered reveal surface has no visible geometry');
  checkRequest();
  await cdp.send('Input.dispatchMouseEvent',{type:'mouseMoved',...hover});
  if (control.reveal_hover_control) {
    const controlPoint=await tab.playwright.locator(control.selector).evaluate(e=>{
      const r=e.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2;
      return r.width>0&&r.height>0&&x>=0&&x<innerWidth&&y>=0&&y<innerHeight?{x,y}:null;
    });
    if (!controlPoint) throw new Error('Registered hover control has no viewport geometry');
    checkRequest();
    await cdp.send('Input.dispatchMouseEvent',{type:'mouseMoved',...controlPoint});
  }
  const deadline=performance.now()+3000;
  let previous=null, stableSince=null;
  while(performance.now()<deadline) {
    checkRequest();
    const point=await tab.playwright.locator(control.selector).evaluate(e=>{
      const r=e.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2;
      let visible=r.width>0&&r.height>0&&x>=0&&x<innerWidth&&y>=0&&y<innerHeight;
      for(let n=e;n;n=n.parentElement){const s=getComputedStyle(n);
        if(s.display==='none'||s.visibility!=='visible'||Number(s.opacity)===0)visible=false;}
      return {x,y,hit:visible&&e.contains(document.elementFromPoint(x,y))};
    });
    const stable=point.hit&&previous&&Math.abs(point.x-previous.x)<.1&&Math.abs(point.y-previous.y)<.1;
    stableSince=stable ? (stableSince??performance.now()) : null;
    previous=point;
    if(stableSince!==null&&performance.now()-stableSince>=150){
      checkRequest();
      await cdp.send('Input.dispatchMouseEvent',{type:'mouseMoved',x:point.x,y:point.y});
      await tab.playwright.locator(control.selector).click({timeoutMs:1500});
      return {input_method:'revealed_stable_click',x:point.x,y:point.y};
    }
    await new Promise(resolve=>setTimeout(resolve,50));
  }
  throw new Error('Registered control remained moving or obstructed');
}

export async function createBrowserControl({directory, browser, tab, observationExpression, continuousFocus=true, retainedTabs=[]}) {
  await fs.mkdir(directory, {recursive: true});
  const sessionId = randomUUID(), feedTab = tab;
  let current = tab, lastRequest = null, articleRedirect = null, pendingPublication = null;
  async function retainForHandoff() {
    for (const kept of new Set([feedTab,current,...retainedTabs])) await kept.markHandoff?.();
  }
  let clockAnchor;
  const visited = new Set();
  let focus = null;
  const focusName = '__windowsFocus_' + sessionId.replaceAll('-', '');
  if (continuousFocus && tab.capabilities &&
      (await tab.capabilities.list()).some(c => c.id === 'cdp')) {
    const cdp = await tab.capabilities.get('cdp');
    const source = `(() => {
      if (window !== window.top) return;
      const key=${JSON.stringify(focusName)}, owner=${JSON.stringify(sessionId)},
        tabId=${JSON.stringify(feedTab.id)}, cleanup=key+'_cleanup';
      if (window[cleanup]) return;
      const buffer=window[key]={protocol:'windows-tab-focus-v2',session_id:owner,tab_id:tabId,
        document_id:crypto.randomUUID(),samples:[],truncated:false};
      const emit=()=>{
        if(buffer.samples.length>=5000){buffer.truncated=true;return;}
        buffer.samples.push({sequence:buffer.samples.length+1,observed_epoch:Date.now()/1000,
          tab_active:document.visibilityState==='visible'&&document.hasFocus(),host:location.hostname,url:location.href});
      };
      const timer=setInterval(emit,1000);
      document.addEventListener('visibilitychange',emit);
      window.addEventListener('focus',emit);
      window.addEventListener('blur',emit);
      window[cleanup]=()=>{clearInterval(timer);document.removeEventListener('visibilitychange',emit);
        window.removeEventListener('focus',emit);window.removeEventListener('blur',emit);};
      emit();
    })()`;
    const installed=await cdp.send('Runtime.evaluate',{expression:source});
    if (installed.exceptionDetails) throw new Error('Continuous focus listener did not start');
    focus={cdp,source,seen:new Map(),
      file:path.resolve(directory,'focus-'+sessionId+'.jsonl')};
  }
  async function drainFocus() {
    if (!focus) return;
    const reply=await focus.cdp.send('Runtime.evaluate',{
      expression:`window[${JSON.stringify(focusName)}] || null`,returnByValue:true});
    if (reply.exceptionDetails) throw new Error('Continuous focus buffer could not be read');
    const data=reply.result?.value;
    if (!data) return; // The next registered-document observation installs it.
    if (data.protocol!=='windows-tab-focus-v2' || data.session_id!==sessionId ||
        String(data.tab_id)!==String(feedTab.id) || !data.document_id || data.truncated ||
        !Array.isArray(data.samples)) throw new Error('Continuous focus buffer has no pinned-tab ownership');
    const previous=focus.seen.get(data.document_id)||0, rows=[];
    for (const p of data.samples) {
      if (!Number.isInteger(p.sequence) || !Number.isFinite(p.observed_epoch) ||
          typeof p.tab_active!=='boolean' || typeof p.host!=='string')
        throw new Error('Malformed continuous focus sample');
      if (p.sequence<=previous) continue;
      rows.push({event_type:'windows_observation',payload:{observed_epoch:p.observed_epoch,
        reason:'browser-tab-focus:continuous',state:{tab_active:p.tab_active,host:p.host}},
        focus_source:{method:'Runtime.evaluate',tab_id:feedTab.id,protocol:data.protocol,
          session_id:data.session_id,document_id:data.document_id,sample:p}});
    }
    if (rows.length) await fs.appendFile(focus.file,rows.map(x=>JSON.stringify(x)+'\n').join(''));
    focus.seen.set(data.document_id,data.samples.length);
  }
  async function atomic(name, value) {
    const temporary = path.join(directory, name + '.tmp');
    await fs.writeFile(temporary, JSON.stringify(value));
    // Retry only Windows file publication, never the browser operation.
    for (let attempt = 0; ; attempt++) {
      try {await fs.rename(temporary, path.join(directory, name)); break;}
      catch (e) {
        if (!['EPERM', 'EACCES', 'EBUSY'].includes(e.code) || attempt >= 9) throw e;
        await new Promise(resolve => setTimeout(resolve, 20));
      }
    }
  }
  async function heartbeat(status = 'ready') {
    // Windows precise time and the control worker's wall clock can disagree.
    // Anchor both peers to the same workspace filesystem clock, retaining the
    // measured uncertainty instead of relaxing the request lifetime.
    const before = performance.now();
    await atomic('consumer-clock.json', {session_id:sessionId,consumer_epoch:Date.now()/1000});
    const reference = await fs.stat(path.join(directory,'consumer-clock.json'));
    const after = performance.now();
    if (after-before > 1000) throw new Error('Workspace clock calibration is too uncertain');
    clockAnchor = {epoch:reference.mtimeMs/1000,before,after};
    await atomic('session.json', {protocol: 'windows-browser-use-v1', session_id: sessionId,
      status, tab_id: feedTab.id, browser_id: browser.browserId,
      ...(focus ? {focus_protocol:'windows-tab-focus-v2',focus_events_path:focus.file} : {}),
      clock_source:'windows_workspace_file_mtime',
      clock_uncertainty_seconds:(after-before)/1000,
      consumer_clock_offset_seconds:reference.mtimeMs/1000-Date.now()/1000,
      heartbeat_epoch: reference.mtimeMs/1000});
  }
  async function publishPendingResponse() {
    await atomic('response.json', pendingPublication.response);
    await fs.appendFile(path.join(directory, 'transport_events.jsonl'),
      JSON.stringify(pendingPublication) + '\n');
    pendingPublication = null;
  }
  function hostEpochBounds() {
    const now=performance.now();
    return [clockAnchor.epoch+(now-clockAnchor.after)/1000,
            clockAnchor.epoch+(now-clockAnchor.before)/1000];
  }
  async function observe(target) {
    let spec = target.semantic_binding || {};
    const url = await current.url();
    let redirectEvidence=null;
    if (!target.expected_hosts?.includes(new URL(url).hostname)) {
      if (!spec.allow_external_article_redirects || articleRedirect?.final_url !== url)
        throw new Error('Target left the registered hosts');
      const article=await current.playwright.evaluate(()=>{
        const visible=e=>{const r=e.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(e).visibility!=='hidden';};
        const roots=Array.from(document.querySelectorAll('article')).filter(visible);
        const titles=Array.from(document.querySelectorAll('h1')).filter(visible);
        return {article_count:roots.length,title_count:titles.length,
          title:titles.length===1?titles[0].innerText.trim():'',
          article_chars:roots.length===1?roots[0].innerText.trim().length:0};
      });
      if(article.article_count!==1||article.title_count!==1||!article.title||article.article_chars<200)
        throw new Error('External redirect has no independent article evidence');
      redirectEvidence={...articleRedirect,...article};
      spec={...spec,detail_selector:'article',detail_path_pattern:null,detail_scroll_selector:null};
    }
    // Navigation disposes the old document's timer. Install on the newly
    // loaded, registered document before taking its first observation.
    if (focus) {
      const installed=await focus.cdp.send('Runtime.evaluate',{expression:focus.source});
      if (installed.exceptionDetails) throw new Error('Continuous focus listener did not start');
    }
    const selected = await browser.tabs.selected();
    // Extension selection metadata can lag real tab activation. Query the
    // pinned document through its supported capability, never a command receipt.
    const tabFocus = await readTabFocus(browser, current);
    const expression = observationExpression.replace('__WINDOWS_BINDING__', JSON.stringify(spec))
      .replace('document.hasFocus()', JSON.stringify(tabFocus.focused));
    const rows = await current.playwright.evaluate(expression);
    if (rows.length !== 1) throw new Error('Ambiguous shared page observation');
    if(spec.media_progress_metric==='decoded_frames')
      rows[0].media_progress = await readDecodedFrames(current,spec.media_selector||'video');
    if (tabFocus.source === 'document_focus') rows[0].tab_active = tabFocus.visible && tabFocus.focused;
    rows[0].tab_focus_source = tabFocus.source;
    if(redirectEvidence)rows[0].article_redirect=redirectEvidence;
    return {state: rows[0], tab_id: current.id, selected_tab_id: selected?.id, url};
  }
  async function perform(request) {
    const {target, action, parameters = {}} = request, spec = target.semantic_binding || {};
    let before = await observe(target);
    if (request.focus_required !== false && before.state.tab_active !== true)
      throw new Error('Pinned tab is not focused; no input');
    await drainFocus(); // Preserve this document before any controlled navigation.
    if (!before.state.allowed || before.state.blocked) throw new Error('Blocked target; no input');
    if(spec.reveal_media_viewport&&['ensure_live_active','ensure_paused','ensure_playing'].includes(action)){
      await revealMediaViewport(current,spec.media_selector||'video',()=>checkRequest(request));
      before=await observe(target);
      if(!before.state.allowed||before.state.blocked)throw new Error('Blocked target after media reveal');
      if(action==='ensure_live_active'&&before.state.playing)return before;
    }
    if (['ensure_content_feed', 'recover_content_feed'].includes(action)) {
      if (!before.state.feed_ready) throw new Error('Registered feed is not ready');
      return before;
    }
    if (action === 'dismiss_popup') {
      const rules = (spec.benign_popups || []).filter(p => p.id === parameters.popup_id);
      if (rules.length !== 1 || !before.state.benign_popups?.includes(parameters.popup_id))
        throw new Error('Popup does not match one registered benign rule');
      const rule = rules[0], button = current.playwright.locator(rule.dismiss_selector);
      if (await button.count() !== 1 ||
          (rule.dismiss_text && (await button.innerText()).trim() !== rule.dismiss_text))
        throw new Error('Registered popup button is missing or ambiguous');
      checkRequest(request);
      await button.click({timeoutMs:4000});
      const after = await observe(target);
      if (after.state.present_popups?.includes(parameters.popup_id))
        throw new Error('Registered popup remains after its bounded action');
      return after;
    }
    const control = spec.controls?.[action];
    if (action==='open_music_player' && spec.player_embedded && before.state.media_present)
      return before;
    if (action==='start_music_playback' && !control) {
      if (before.state.media_present && before.state.playing) return before;
      const resume=spec.controls?.ensure_playing;
      if (!before.state.media_present || !resume?.selector)
        throw new Error('Music playback has no verified resume control');
      checkRequest(request);
      await current.playwright.locator(resume.selector).click({timeoutMs:4000});
      return observe(target);
    }
    if ((action==='ensure_paused'&&before.state.paused) ||
        (action==='ensure_playing'&&before.state.playing)) return before;
    if(control?.reveal_hover_selector) {
      if(!control.selector) throw new Error('Missing registered revealed control');
      const evidence=await clickRevealedControl(current,control,()=>checkRequest(request));
      return {...await observe(target),control_evidence:evidence};
    }
    if (['advance_feed', 'scroll_content'].includes(action) || control?.input === 'wheel') {
      const selector = before.state.detail_open ? spec.detail_scroll_selector : spec.feed_scroll_selector;
      const capabilities = current.capabilities ? await current.capabilities.list() : [];
      if (capabilities.some(c => c.id === 'cdp')) {
        const geometry = await current.playwright.locator(selector || 'body').evaluate(e => {
          const v=document.documentElement;
          const pageRoot=e===document.body||e===document.documentElement||e===document.scrollingElement;
          const r=pageRoot?{left:0,right:v.clientWidth,top:0,bottom:v.clientHeight}:e.getBoundingClientRect();
          const left=Math.max(0,r.left), right=Math.min(v.clientWidth,r.right);
          const top=Math.max(0,r.top), bottom=Math.min(v.clientHeight,r.bottom);
          if (right<=left || bottom<=top) return null;
          return {x:(left+right)/2,y:(top+bottom)/2,deltaY:Math.round(v.clientHeight*.72)};
        });
        if (!geometry) throw new Error('Registered scroll target is outside the viewport');
        const cdp = await current.capabilities.get('cdp');
        checkRequest(request);
        await cdp.send('Input.dispatchMouseEvent', {type:'mouseWheel',deltaX:0,...geometry});
        return observe(target);
      }
      checkRequest(request);
      await current.playwright.locator(selector || 'body').press('PageDown', {timeoutMs: 4000});
      return observe(target);
    }
    if (!control?.selector) throw new Error('No registered control for ' + action);
    const visibleLinkNavigation = control.browser_use_input === 'navigate_visible_link';
    if (control.opens_new_tab && !visibleLinkNavigation)
      throw new Error('New-tab actions require popup ownership evidence unavailable in this transport');
    if (control.input === 'registered_entry') {
      const entries = (target.args || []).filter(u => /^https?:\/\//.test(u));
      if (action !== 'return_to_feed' || !before.state.detail_open || entries.length !== 1)
        throw new Error('Registered-entry return requires a verified detail and one entry');
      checkRequest(request);
      // This transport only mutates the explicitly pinned tab.
      await current.goto(entries[0]);
      articleRedirect=null;
      await current.playwright.locator(spec.feed_selector).first().waitFor({state:'visible',timeoutMs:4000});
      return observe(target);
    }
    if (control.input) throw new Error('Unsupported bound input: ' + control.input);
    if (control.browser_use_input && !visibleLinkNavigation)
      throw new Error('Unsupported browser-use input');
    if (['scroll_up','scroll_down'].includes(control.reveal)) {
      await revealScrolledControl(current,control.selector,control.reveal,()=>checkRequest(request));
      before=await observe(target);
      if (!before.state.allowed || before.state.blocked) throw new Error('Blocked target after scroll reveal');
    }
    const visiblePoints=selector=>current.playwright.locator(selector).evaluateAll(es=>es.map(e=>{
      const r=e.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2;
      return {x,y,hit:r.width>0&&r.height>0&&x>=0&&x<innerWidth&&y>=0&&y<innerHeight&&
        e.contains(document.elementFromPoint(x,y))};
    }).filter(p=>p.hit));
    for(const step of control.reveal_steps || []) {
      if(step.skip_if_visible && (await visiblePoints(step.skip_if_visible)).length)continue;
      if(!['click','hover'].includes(step.action))throw new Error('Unsupported registered reveal step');
      let previous=null,stableSince=null,point=null;
      const deadline=performance.now()+2500;
      while(performance.now()<deadline){
        checkRequest(request);
        const points=await visiblePoints(step.selector);
        if(points.length>1)throw new Error('Ambiguous registered reveal control');
        point=points[0];
        const stable=point&&previous&&Math.abs(point.x-previous.x)<.1&&Math.abs(point.y-previous.y)<.1;
        stableSince=stable?(stableSince??performance.now()):null;previous=point;
        if(stableSince!==null&&performance.now()-stableSince>=150)break;
        point=null;await new Promise(resolve=>setTimeout(resolve,50));
      }
      if(!point)throw new Error('Registered reveal control is obscured');
      checkRequest(request);
      if(step.action==='click')await current.playwright.locator(step.selector).click({timeoutMs:1500});
      else {const cdp=await current.capabilities.get('cdp');
        await cdp.send('Input.dispatchMouseEvent',{type:'mouseMoved',x:point.x,y:point.y});}
    }
    if(control.reveal_steps?.length){
      const deadline=performance.now()+2500;
      while(!(await visiblePoints(control.selector)).length){
        checkRequest(request);
        if(performance.now()>=deadline)throw new Error('Registered revealed content remained hidden');
        await new Promise(resolve=>setTimeout(resolve,50));
      }
    }
    const candidates = await current.playwright.locator(control.selector).evaluateAll((elements, c) =>
      elements.map((e, index) => ({index,
        visible: (() => {
          const r=e.getBoundingClientRect(), viewport=document.documentElement;
          if (!(r.width>0 && r.height>0 && r.right>0 && r.left<viewport.clientWidth &&
                r.bottom>0 && r.top<viewport.clientHeight)) return false;
          for (let node=e; node; node=node.parentElement) {
            const style=getComputedStyle(node);
            if (style.display==='none' || ['hidden','collapse'].includes(style.visibility) ||
                Number(style.opacity)===0) return false;
          }
          const hit=document.elementFromPoint(
            (Math.max(0,r.left)+Math.min(viewport.clientWidth,r.right))/2,
            (Math.max(0,r.top)+Math.min(viewport.clientHeight,r.bottom))/2);
          return hit===e || e.contains(hit);
        })(),
        identity: (c.identity_ancestor ? e.closest(c.identity_ancestor) : e)
          ?.getAttribute(c.identity_attribute || 'href') || e.textContent?.trim(),
        text: e.textContent?.trim(),
        href: e.closest('a')?.getAttribute('href') || null,
        destination: c.destination_selector ?
          (c.identity_ancestor ? e.closest(c.identity_ancestor) : e)?.querySelector(c.destination_selector)
            ?.getAttribute(c.destination_attribute || 'href') : e.closest('a')?.getAttribute('href')})), control);
    const eligible = candidates.filter(c => {
      if (!c.identity || (visibleLinkNavigation && !c.visible) ||
          (control.avoid_repeat && visited.has(c.destination || c.identity))) return false;
      if (control.href_path_pattern || control.exclude_current) {
        let destination;
        try { destination = new URL(c.destination || c.href, before.url); }
        catch { return false; }
        if (control.href_path_pattern && !new RegExp(control.href_path_pattern).test(destination.pathname)) return false;
        if (control.exclude_current && destination.origin === new URL(before.url).origin &&
            destination.pathname === new URL(before.url).pathname) return false;
      }
      return true;
    });
    if (!eligible.length) throw new Error('No new registered content controls');
    if (control.selection !== 'random' && candidates.length !== 1)
      throw new Error('Ambiguous registered control');
    const fraction = Math.max(0, Math.min(0.999999, Number(parameters.choice_fraction) || 0));
    const choice = eligible[control.selection === 'random' ? Math.floor(fraction * eligible.length) : 0];
    if (visibleLinkNavigation) {
      const destination = new URL(choice.destination, before.url);
      const browsing=action==='open_feed_content';
      const live=['enter_live_room','switch_live_room'].includes(action);
      const longVideo=['enter_long_video','switch_long_video'].includes(action);
      const route=browsing?spec.detail_path_pattern:spec.content_path_pattern;
      const hosts=browsing?spec.content_hosts:target.expected_hosts;
      const sourceReady=browsing?before.state.feed_ready:
        ['enter_live_room','enter_long_video'].includes(action)?before.state.feed_ready:before.state.content_page;
      if ((!browsing&&!live&&!longVideo) || !sourceReady ||
          !['https:', 'http:'].includes(destination.protocol) ||
          !hosts?.includes(destination.hostname) ||
          !route || !new RegExp(route).test(destination.pathname))
        throw new Error('Visible content link is outside the registered detail route');
      checkRequest(request);
      await current.goto(destination.href);
      const finalUrl=await current.url();
      articleRedirect=browsing&&spec.allow_external_article_redirects&&
        !target.expected_hosts.includes(new URL(finalUrl).hostname) ?
        {source_url:before.url,link_url:destination.href,link_text:choice.text,
          link_identity:choice.identity,final_url:finalUrl} : null;
      choice.input_method = 'navigate_visible_link';
    } else {
      checkRequest(request);
      await current.playwright.locator(control.selector).nth(choice.index).click({timeoutMs: 4000});
      choice.input_method = 'click';
    }
    if(spec.reveal_media_viewport&&['enter_live_room','switch_live_room'].includes(action))
      await revealMediaViewport(current,spec.media_selector||'video',()=>checkRequest(request));
    if (action==='open_feed_content' && spec.detail_selector) {
      checkRequest(request);
      await current.playwright.locator(spec.detail_selector).first().waitFor({state:'visible',timeoutMs:4000});
      checkRequest(request);
    }
    const after = await observe(target);
    if (action === 'open_feed_content') {
      if (!after.state.detail_open) throw new Error('Content click has no independent detail evidence');
      visited.add(choice.destination || choice.identity);
    }
    return {...after, control_evidence: choice};
  }
  function checkRequest(request) {
    const [earliest,latest] = hostEpochBounds();
    if (request.protocol !== 'windows-browser-use-v1' || request.session_id !== sessionId
        || !Number.isFinite(request.created_epoch) || !Number.isFinite(request.expires_epoch)
        || request.created_epoch > latest + .01 || request.expires_epoch < latest
        || request.expires_epoch <= request.created_epoch
        || request.expires_epoch - request.created_epoch > 90)
      throw new Error('Expired or mismatched browser-use request');
  }
  async function process(request) {
    checkRequest(request);
    if (request.operation === 'launch') {
      if (current.id !== feedTab.id || !matchesRegisteredEntry(await feedTab.url(),request.entry_url,
          request.target?.semantic_binding?.entry_tracking_query_keys || []))
        throw new Error('Fresh registered entry is not open in the pinned feed tab');
      // Selecting an extension tab does not activate its Windows window.
      // Foreground duration remains independently checked by the native logger.
      checkRequest(request);
      const cdp = await feedTab.capabilities.get('cdp');
      await cdp.send('Page.bringToFront');
      checkRequest(request);
      const tabFocus = await readTabFocus(browser, feedTab);
      if (request.focus_required !== false && (!tabFocus.focused || tabFocus.visible === false))
        throw new Error('Pinned tab did not receive browser focus');
      visited.clear();
      return {tab_id: feedTab.id, url: await feedTab.url()};
    }
    if (request.operation === 'observe') return observe(request.target);
    if (request.operation === 'perform') return perform(request);
    throw new Error('Unsupported browser-use operation');
  }
  await heartbeat();
  await retainForHandoff();
  return {
    currentTab() {return current;},
    async serve(seconds = 25) {
      const deadline = performance.now() + Math.min(50, seconds) * 1000;
      let served = 0, lastHeartbeat = 0;
      try {
      while (performance.now() < deadline) {
        if (performance.now() - lastHeartbeat > 2000 || !lastHeartbeat) {
          await drainFocus(); await heartbeat(); lastHeartbeat = performance.now();
        }
        if (pendingPublication) {
          await publishPendingResponse(); served++; continue;
        }
        let request;
        try {request = JSON.parse(await fs.readFile(path.join(directory, 'request.json'), 'utf8'));}
        catch (e) {if (e.code !== 'ENOENT') throw e;}
        if (request && request.request_id !== lastRequest) {
          lastRequest = request.request_id;
          let response = {request_id: request.request_id, session_id: sessionId};
          try {const result = await process(request); checkRequest(request);
            response = {...response, ok: true, result};}
          catch (e) {response = {...response, ok: false, error: String(e.message)};}
          response.completed_epoch_bounds = hostEpochBounds();
          response.completed_epoch = response.completed_epoch_bounds[1];
          response.clock_source = 'windows_workspace_file_mtime';
          pendingPublication = {
            request: {...request, target: request.target ? {name: request.target.name} : undefined},
            response};
          await publishPendingResponse();
          served++;
        } else await new Promise(resolve => setTimeout(resolve, 50));
      }
      await drainFocus();
      return {served, current_tab_id: current.id, session_id: sessionId};
      } finally { await retainForHandoff(); }
    },
    async close() {
      await drainFocus();
      if (focus) {
        await focus.cdp.send('Runtime.evaluate',{expression:
          `window[${JSON.stringify(focusName+'_cleanup')}]?.(); delete window[${JSON.stringify(focusName+'_cleanup')}];`});
        await focus.cdp.send('Runtime.evaluate',{expression:`delete window[${JSON.stringify(focusName)}];`});
      }
      await heartbeat('closed');
      await retainForHandoff();
    }
  };
}
