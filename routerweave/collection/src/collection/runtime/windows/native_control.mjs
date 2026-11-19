// Official Sky consumer for the shared Windows collector. No app-specific runner.
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

export function parseNativeState(tree, window, binding) {
  const lines = tree.split('\n');
  const controls = lines.filter(line => line.trimEnd().endsWith(` ID: ${binding.playback_control_id}`));
  const control = controls.length === 1 ? controls[0].match(/^\s*(\d+)\s+(?:按钮|菜单项|Button|MenuItem)\s+(\S+)\s+ID:/) : null;
  const blocked = /(?:对话框|\bdialog\b)/i.test(tree);
  return {allowed: Boolean(control) && !blocked, blocked,
    media_present: Boolean(control), playing: control?.[2] === binding.playing_name,
    paused: control?.[2] === binding.paused_name,
    media_identity: window.title || '', control_index: control ? Number(control[1]) : null,
    native_ui: {window_id: window.id, executable: window.app, title: window.title,
      playback_line: controls.length === 1 ? controls[0].trim() : null}};
}

export async function createNativeControl({directory, sky, window, binding}) {
  if (window.app.toLowerCase() !== binding.executable.toLowerCase()) throw Error('Native executable mismatch');
  await fs.mkdir(directory, {recursive:true});
  const sessionId = crypto.randomUUID();
  let lastRequest, pending, latest, baseEpoch, baseMono;
  async function atomic(name, value) {
    const temp = path.join(directory, `${crypto.randomUUID()}.tmp`);
    await fs.writeFile(temp, JSON.stringify(value));
    for(let attempt=0;;attempt++) {
      try {await fs.rename(temp,path.join(directory,name));break;}
      catch(e) {
        if(!['EPERM','EACCES','EBUSY'].includes(e.code)) throw e;
        if(attempt>=9) {
          // The transport ignores partial JSON and accepts only exact request/session IDs.
          await fs.writeFile(path.join(directory,name),JSON.stringify(value));break;
        }
        await new Promise(r=>setTimeout(r,25));
      }
    }
  }
  async function syncClock() {
    const p = path.join(directory,'consumer-clock.json');
    await fs.writeFile(p, '{}'); baseEpoch=(await fs.stat(p)).mtimeMs/1000; baseMono=performance.now();
  }
  const now=()=>baseEpoch+(performance.now()-baseMono)/1000;
  async function heartbeat(status='ready') {
    await syncClock();
    await atomic('session.json',{protocol:'windows-native-use-v1',session_id:sessionId,
      status, window_id:window.id, executable:window.app, heartbeat_epoch:now(),
      clock_source:'windows_workspace_file_mtime'});
  }
  function check(request) {
    if (request.protocol!=='windows-native-use-v1' || request.session_id!==sessionId
        || !(request.created_epoch<=now() && now()<=request.expires_epoch)
        || request.target?.native_binding?.executable?.toLowerCase()!==binding.executable.toLowerCase())
      throw Error('Expired or mismatched native request');
  }
  async function observe(forInput=false) {
    latest=await sky.get_window_state({window,include_screenshot:forInput,include_text:true});
    window=latest.window;
    const tree=latest.accessibility?.tree || '';
    const state=parseNativeState(tree,window,binding);
    await fs.appendFile(path.join(directory,'observations.jsonl'),JSON.stringify({epoch:now(),tree,window,state})+'\n');
    return {window_id:window.id,executable:window.app,state};
  }
  async function respond(request,result,error) {
    await syncClock();
    const response={request_id:request.request_id,session_id:sessionId,completed_epoch:now(),
      ok:!error,...(error?{error:String(error.message||error)}:{result})};
    await atomic('response.json',response);
    await fs.appendFile(path.join(directory,'transport_events.jsonl'),JSON.stringify({request,response})+'\n');
  }
  await heartbeat();
  return {
    async serve(seconds=45) {
      if(pending) return pending;
      const deadline=performance.now()+Math.min(45,seconds)*1000;
      let beat=0,served=0;
      while(performance.now()<deadline) {
        if(performance.now()-beat>2000) {await heartbeat();beat=performance.now();}
        let request;try {request=JSON.parse(await fs.readFile(path.join(directory,'request.json'),'utf8'));}
        catch(e) {if(e.code!=='ENOENT') throw e;}
        if(request && request.request_id!==lastRequest) {
          lastRequest=request.request_id;
          try {
            check(request);
            const observed=await observe();
            if(!observed.state.allowed) throw Error('Native playback UI missing or blocked');
            if(request.operation==='launch') {
              if(binding.entry_text && !latest.accessibility.tree.includes(binding.entry_text)) throw Error('Fresh registered native entry required');
              await sky.activate_window({window});
              await respond(request,observed);
            } else if(request.operation==='activate') {
              await sky.activate_window({window});
              await respond(request,await observe());
            } else if(request.operation==='observe') await respond(request,observed);
            else if(request.operation==='perform') {
              const action=request.action;
              if(['open_music_player'].includes(action)
                  || (['start_music_playback','ensure_playing'].includes(action) && observed.state.playing)
                  || (action==='ensure_paused' && observed.state.paused)) await respond(request,observed);
              else {
                const supported=['start_music_playback','ensure_playing','ensure_paused','advance_track'];
                if(!supported.includes(action)) throw Error('Unbound native action');
                await sky.activate_window({window});
                await observe(true);
                pending={request,action,tree:latest.accessibility.tree,window};
                return pending;
              }
            } else throw Error('Unsupported native operation');
            served++;
          } catch(e) {await respond(request,null,e);}
        } else await new Promise(r=>setTimeout(r,50));
      }
      return {served,session_id:sessionId};
    },
    async execute(elementIndex) {
      if(!pending) throw Error('No observed native action pending');
      const p=pending;pending=null;
      try {
        check(p.request);
        const parsed=parseNativeState(p.tree,p.window,binding);
        const candidates=p.action==='advance_track'
          ? p.tree.split('\n').filter(l=>new RegExp(`^\\s*${elementIndex}\\s+(?:按钮|Button)\\s+${binding.next_name}$`).test(l))
          : parsed.control_index===elementIndex?[elementIndex]:[];
        if(candidates.length!==1) throw Error('Input does not match freshly observed bound control');
        await sky.click({window:p.window,element_index:elementIndex});
        const result=await observe();check(p.request);await respond(p.request,result);
        return result;
      } catch(e) {await respond(p.request,null,e);throw e;}
    },
    async close() {await heartbeat('closed');}
  };
}

// Chat uses the same official native transport, with no per-message agent step.
// Patterns are retained, device-verified app facts; element indexes are always
// resolved from the latest state. Raw UI trees and message text are not logged.
