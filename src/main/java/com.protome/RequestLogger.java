package com.protome;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.http.message.requests.HttpRequest; // FIXED IMPORT
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;

public class RequestLogger {
    private MontoyaApi api;
    private DefaultTableModel tableModel;
    private JTable table;
    private HttpRequestEditor requestViewer;
    private JPanel uiComponent;

    public RequestLogger(MontoyaApi api) {
        this.api = api;

        // Table setup
        String[] columns = {"ID", "Method", "URL", "Mutation", "Time"};
        tableModel = new DefaultTableModel(columns, 0);
        table = new JTable(tableModel);

        // Viewer setup (The Burp Request Viewer)
        requestViewer = api.userInterface().createHttpRequestEditor(burp.api.montoya.ui.editor.EditorOptions.READ_ONLY);

        // Layout
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setTopComponent(new JScrollPane(table));
        splitPane.setBottomComponent(requestViewer.uiComponent());

        uiComponent = new JPanel(new BorderLayout());
        uiComponent.add(splitPane, BorderLayout.CENTER);

        // Listener: When clicking a row, show the request in the viewer
        table.getSelectionModel().addListSelectionListener(e -> {
            int row = table.getSelectedRow();
            if (row != -1) {
                // In a real app, you would store the full HttpRequestResponse object in a list
                // and retrieve it here. For now, we are just showing the text.
            }
        });
    }

    public void log(HttpRequest request, String mutation) {
        SwingUtilities.invokeLater(() -> {
            tableModel.addRow(new Object[]{
                    tableModel.getRowCount() + 1,
                    request.method(),
                    request.url(),
                    mutation != null ? mutation : "-",
                    java.time.LocalTime.now().toString()
            });
            // Update the viewer immediately with the latest request (for simplicity)
            requestViewer.setRequest(request);
        });
    }

    public Component getUiComponent() {
        return uiComponent;
    }
}
