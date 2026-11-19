package org.testbed.mobile;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.app.UiAutomation;
import android.app.ActivityManager;
import android.content.Intent;
import android.content.res.Configuration;
import android.graphics.Rect;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Bundle;
import android.util.Base64;
import android.os.SystemClock;
import android.util.Xml;
import android.view.accessibility.AccessibilityNodeInfo;
import java.io.StringWriter;
import org.xmlpull.v1.XmlSerializer;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.List;
import java.util.ConcurrentModificationException;

/** Bounded native observations and identity-checked removal of one recent task. */
public final class AndroidNativeBridge {
    private static volatile int nodes;
    private static volatile String phase = "starting";
    private static long startedAt;

    private static void phase(String value) {
        phase = value;
        System.err.println("native snapshot phase=" + value + " elapsed_ms="
            + (SystemClock.elapsedRealtime() - startedAt) + " nodes=" + nodes);
    }

    public static void main(String[] args) {
        startedAt = SystemClock.elapsedRealtime();
        final int snapshotSeconds = args.length >= 2 && args[0].equals("snapshot")
            ? Integer.parseInt(args[1]) : 8;
        if (snapshotSeconds < 8 || snapshotSeconds > 16)
            throw new IllegalArgumentException("snapshot deadline must be 8..16 seconds");
        // Bound remote lifetime as well as the host ADB timeout: a blocked
        // accessibility Binder call must not leave a competing UI connection.
        Thread watchdog = new Thread(() -> {
            try { Thread.sleep(snapshotSeconds * 1000L); }
            catch (InterruptedException stopped) { return; }
            System.err.println("Android native operation exceeded " + snapshotSeconds + " seconds; phase="
                + phase + " nodes=" + nodes);
            Runtime.getRuntime().halt(2);
        }, "mobile-control-native-deadline");
        watchdog.setDaemon(true);
        watchdog.start();
        if (args.length > 0 && !args[0].equals("snapshot") && !args[0].equals("set-text")) {
            try { recentTasks(args); }
            catch (Throwable failure) { failure.printStackTrace(System.err); System.exit(1); }
            return;
        }
        HandlerThread thread = new HandlerThread("mobile-control-ui-snapshot");
        UiAutomation automation = null;
        int exitCode = 0;
        try {
            // app_process does not initialize the main looper. Accessibility
            // creates a main-thread Handler even though callbacks use our thread.
            if (Looper.getMainLooper() == null) Looper.prepareMainLooper();
            thread.start();
            Class<?> connectionType = Class.forName("android.app.IUiAutomationConnection");
            Object connection = Class.forName("android.app.UiAutomationConnection")
                .getDeclaredConstructor().newInstance();
            automation = (UiAutomation) UiAutomation.class
                .getConstructor(Looper.class, connectionType)
                .newInstance(thread.getLooper(), connection);
            phase("connect");
            UiAutomation.class.getMethod("connect").invoke(automation);
            phase("configure");
            AccessibilityServiceInfo service = automation.getServiceInfo();
            service.flags |= AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS;
            if (args.length == 3 && args[2].equals("important"))
                service.flags &= ~AccessibilityServiceInfo.FLAG_INCLUDE_NOT_IMPORTANT_VIEWS;
            else service.flags |= AccessibilityServiceInfo.FLAG_INCLUDE_NOT_IMPORTANT_VIEWS;
            automation.setServiceInfo(service);
            phase("root");
            AccessibilityNodeInfo root = currentRoot(automation);
            if (args.length == 2 && args[0].equals("set-text")) {
                JSONObject input = new JSONObject(new String(Base64.decode(args[1], Base64.DEFAULT), "UTF-8"));
                String app = input.getString("app_id");
                String resource = input.getString("resource_id");
                String text = input.getString("text");
                if (!app.equals(String.valueOf(root.getPackageName())) ||
                    !resource.startsWith(app + ":id/") || text.isEmpty() || text.length() > 4096)
                    throw new IllegalArgumentException("Invalid target-scoped text operation");
                List<AccessibilityNodeInfo> matches = root.findAccessibilityNodeInfosByViewId(resource);
                try {
                    if (matches.size() != 1) throw new IllegalStateException("Editor is not unique");
                    AccessibilityNodeInfo editor = matches.get(0);
                    if (!editor.isEditable() || !editor.isEnabled() || !editor.isVisibleToUser() ||
                        (editor.getText() != null && editor.getText().length() != 0))
                        throw new IllegalStateException("Editor is unavailable or has a draft");
                    Bundle arguments = new Bundle();
                    arguments.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text);
                    if (!editor.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, arguments))
                        throw new IllegalStateException("Text operation was not accepted");
                    System.out.println("{\"accepted\":true}");
                } finally {
                    for (AccessibilityNodeInfo node : matches) node.recycle();
                    root.recycle();
                }
                return;
            }
            for (int attempt = 0; attempt < 3; attempt++) {
                nodes = 0;
                phase("traverse-" + attempt);
                StringWriter output = new StringWriter();
                XmlSerializer xml = Xml.newSerializer();
                xml.setOutput(output);
                xml.startDocument("UTF-8", true);
                xml.startTag(null, "hierarchy");
                try {
                    writeNode(xml, root, 0);
                    xml.endTag(null, "hierarchy");
                    xml.endDocument();
                    // Emit only a complete snapshot, never a partially walked tree.
                    System.out.println(output.toString());
                    phase("complete");
                    break;
                } catch (ConcurrentModificationException changed) {
                    if (attempt == 2) throw changed;
                } finally { root.recycle(); }
                // Dynamic pages can remove a child during traversal. Discard
                // the entire attempt, clear stale nodes, and obtain a new root.
                automation.clearCache();
                phase("root-after-change-" + attempt);
                root = currentRoot(automation);
            }
        } catch (Throwable failure) {
            failure.printStackTrace(System.err);
            exitCode = 1;
        } finally {
            if (automation != null) {
                phase("disconnect");
                try { UiAutomation.class.getMethod("disconnect").invoke(automation); }
                catch (Throwable failure) { failure.printStackTrace(System.err); exitCode = 1; }
            }
            thread.quitSafely();
        }
        System.exit(exitCode);
    }

    private static AccessibilityNodeInfo currentRoot(UiAutomation automation) throws Exception {
        // Both launch and a discarded traversal can cross an activity transition.
        // Wait only for a fresh root, within the bounded operation watchdog;
        // never emit the earlier partial tree or wait for event silence.
        for (int attempt = 0; attempt < 20; attempt++) {
            AccessibilityNodeInfo root = automation.getRootInActiveWindow();
            if (root != null) return root;
            Thread.sleep(150);
        }
        throw new IllegalStateException("current root unavailable");
    }

    private static void recentTasks(String[] args) throws Exception {
        Class<?> serviceType = Class.forName("android.app.IActivityTaskManager");
        Object service = Class.forName("android.app.ActivityTaskManager")
            .getMethod("getService").invoke(null);
        int user = (Integer) ActivityManager.class.getMethod("getCurrentUser").invoke(null);
        Object slice = serviceType.getMethod("getRecentTasks", int.class, int.class, int.class)
            .invoke(service, 1000, 0, user);
        List<?> tasks = (List<?>) Class.forName("android.content.pm.BaseParceledListSlice")
            .getMethod("getList").invoke(slice);
        JSONArray result = new JSONArray();
        boolean remove = args[0].equals("remove-task");
        if (!remove && !args[0].equals("list-recent-tasks")) throw new IllegalArgumentException("command");
        if (remove && (args.length != 3 || !args[1].matches("[0-9]+")
                || !args[2].matches("[A-Za-z0-9_.]+"))) throw new IllegalArgumentException("task identity");
        for (Object value : tasks) {
            ActivityManager.RecentTaskInfo task = (ActivityManager.RecentTaskInfo) value;
            if (task.baseIntent == null || task.baseIntent.getComponent() == null)
                throw new IllegalStateException("recent task package unavailable");
            String pkg = task.baseIntent.getComponent().getPackageName();
            Object taskConfiguration = value.getClass().getField("configuration").get(value);
            Object configuration = Configuration.class.getField("windowConfiguration").get(taskConfiguration);
            int type = (Integer) configuration.getClass().getMethod("getActivityType").invoke(configuration);
            boolean home = task.baseIntent.hasCategory(Intent.CATEGORY_HOME) || type == 2;
            JSONObject row = new JSONObject().put("task_id", task.persistentId)
                .put("app_id", pkg).put("activity_type", type).put("is_home", home);
            result.put(row);
            if (remove && task.persistentId == Integer.parseInt(args[1])) {
                if (!pkg.equals(args[2]) || home || (type != 0 && type != 1))
                    throw new IllegalStateException("recent task identity or type changed");
                boolean removed = (Boolean) serviceType.getMethod("removeTask", int.class)
                    .invoke(service, task.persistentId);
                if (!removed) throw new IllegalStateException("task removal rejected");
                System.out.println(new JSONObject().put("removed", task.persistentId));
                return;
            }
        }
        if (remove) System.out.println(new JSONObject().put("already_absent", Integer.parseInt(args[1])));
        else System.out.println(new JSONObject().put("tasks", result));
    }

    private static void writeNode(XmlSerializer xml, AccessibilityNodeInfo node, int depth)
            throws Exception {
        if (++nodes > 12000 || depth > 100) throw new IllegalStateException("hierarchy limit");
        xml.startTag(null, "node");
        attribute(xml, "text", node.getText());
        attribute(xml, "content-desc", node.getContentDescription());
        attribute(xml, "class", node.getClassName());
        attribute(xml, "package", node.getPackageName());
        attribute(xml, "resource-id", node.getViewIdResourceName());
        attribute(xml, "displayed", Boolean.toString(node.isVisibleToUser()));
        attribute(xml, "enabled", Boolean.toString(node.isEnabled()));
        attribute(xml, "clickable", Boolean.toString(node.isClickable()));
        attribute(xml, "selected", Boolean.toString(node.isSelected()));
        attribute(xml, "checked", Boolean.toString(node.isChecked()));
        Rect bounds = new Rect();
        node.getBoundsInScreen(bounds);
        attribute(xml, "bounds", "[" + bounds.left + "," + bounds.top + "]["
            + bounds.right + "," + bounds.bottom + "]");
        int childCount = node.getChildCount();
        for (int index = 0; index < childCount; index++) {
            AccessibilityNodeInfo child = node.getChild(index);
            if (child == null) throw new ConcurrentModificationException("incomplete current hierarchy");
            try { writeNode(xml, child, depth + 1); } finally { child.recycle(); }
        }
        xml.endTag(null, "node");
    }

    private static void attribute(XmlSerializer xml, String name, CharSequence value)
            throws Exception {
        // Android text may contain XML-forbidden controls; retain printable content.
        String text = value == null ? "" : value.toString();
        xml.attribute(null, name, text.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F]", ""));
    }
}
