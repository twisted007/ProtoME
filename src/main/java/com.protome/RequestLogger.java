package com.protome;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.http.message.requests.HttpRequest;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;

/**
 * RequestLogger — the Logger tab UI.
 *
 * Every time ProtomeHttpHandler successfully transforms a request, it calls
 * logger.log() here. This class records that request in a scrollable table
 * (one row per request) and displays the full request bytes in Burp's native
 * request viewer when a row is selected.
 *
 * Design choice — why a Burp HttpRequestEditor instead of a plain text area:
 *   Burp's HttpRequestEditor gives us syntax highlighting, proper binary display,
 *   and the same viewer users already know from Repeater — for free, with one API call.
 *   A plain JTextArea would show the binary Protobuf body as garbled text.
 *
 * Threading note: log() can be called from Burp's HTTP handler thread, but all
 * Swing UI updates must happen on the Event Dispatch Thread (EDT). SwingUtilities.invokeLater()
 * queues the update to run on the EDT rather than executing it immediately on the
 * handler thread, which would cause race conditions or visual glitches.
 */
public class RequestLogger {
    private MontoyaApi api;
    private DefaultTableModel tableModel;
    private JTable table;
    private HttpRequestEditor requestViewer; // Burp's native request viewer component
    private JPanel uiComponent;

    public RequestLogger(MontoyaApi api) {
        this.api = api;

        // === TABLE: one row per intercepted request ===
        // Columns: sequential ID, HTTP method, full URL, mutation strategy (or "-"), timestamp.
        String[] columns = {"ID", "Method", "URL", "Mutation", "Time"};
        tableModel = new DefaultTableModel(columns, 0);
        table = new JTable(tableModel);

        // === REQUEST VIEWER: Burp's built-in editor in read-only mode ===
        // READ_ONLY prevents the user from accidentally editing the logged request.
        // This viewer understands binary content and renders it correctly even
        // when the body is binary Protobuf rather than readable text.
        requestViewer = api.userInterface().createHttpRequestEditor(burp.api.montoya.ui.editor.EditorOptions.READ_ONLY);

        // === LAYOUT: table on top, viewer below ===
        // A vertical JSplitPane gives both panels space and lets the user resize the split.
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setTopComponent(new JScrollPane(table));
        splitPane.setBottomComponent(requestViewer.uiComponent());

        uiComponent = new JPanel(new BorderLayout());
        uiComponent.add(splitPane, BorderLayout.CENTER);

        // === ROW SELECTION LISTENER ===
        // When the user clicks a row in the table, show the corresponding request
        // in the viewer below. Currently the viewer always shows the most recently
        // logged request (see log() below); a full implementation would store each
        // request object in a list and retrieve it by row index here.
        table.getSelectionModel().addListSelectionListener(e -> {
            int row = table.getSelectedRow();
            if (row != -1) {
                // In a real app, you would store the full HttpRequestResponse object in a list
                // and retrieve it here. For now, we are just showing the text.
            }
        });
    }

    /**
     * Records a transformed request in the log table and updates the viewer.
     * Called by ProtomeHttpHandler after each successful transformation.
     *
     * @param request   The fully-modified request (headers stripped, binary body set).
     * @param mutation  The mutation strategy name, or null if no mutation was applied.
     */
    public void log(HttpRequest request, String mutation) {
        // invokeLater schedules this block to run on the EDT — safe to call from any thread.
        SwingUtilities.invokeLater(() -> {
            tableModel.addRow(new Object[]{
                    tableModel.getRowCount() + 1,        // auto-increment ID
                    request.method(),                    // GET, POST, etc.
                    request.url(),                       // full URL including path
                    mutation != null ? mutation : "-",   // strategy name or dash if none
                    java.time.LocalTime.now().toString() // wall-clock time of interception
            });
            // Update the viewer to show the latest request.
            // A future improvement: store all requests in a list so the viewer
            // can show whichever row the user selects, not just the last one.
            requestViewer.setRequest(request);
        });
    }

    // Returns the complete tab panel so ProtomeExtension can add it to the tabbed pane.
    public Component getUiComponent() {
        return uiComponent;
    }
}
