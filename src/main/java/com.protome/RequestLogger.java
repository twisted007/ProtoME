package com.protome;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.http.message.requests.HttpRequest;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.ArrayDeque;

public class RequestLogger {
    private static final int MAX_LOG_ENTRIES = 1000;

    private MontoyaApi api;
    private DefaultTableModel tableModel;
    private JTable table;
    private HttpRequestEditor requestViewer;
    private JPanel uiComponent;

    // Parallel bounded queue of HttpRequest objects — one per table row, same index.
    private final ArrayDeque<HttpRequest> requestHistory = new ArrayDeque<>();

    // Absolute sequence counter — never resets, so IDs remain meaningful after rolloff.
    private int sequenceCounter = 0;

    // When false, log() is a no-op.
    private volatile boolean loggingEnabled = true;

    public RequestLogger(MontoyaApi api) {
        this.api = api;

        String[] columns = {"ID", "Method", "URL", "Mutation", "Time"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override public boolean isCellEditable(int row, int col) { return false; }
        };
        table = new JTable(tableModel);

        requestViewer = api.userInterface().createHttpRequestEditor(burp.api.montoya.ui.editor.EditorOptions.READ_ONLY);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setTopComponent(new JScrollPane(table));
        splitPane.setBottomComponent(requestViewer.uiComponent());

        // Toggle + label row above the split pane.
        JToggleButton toggleButton = new JToggleButton("Logging: ON", true);
        toggleButton.addActionListener(e -> {
            loggingEnabled = toggleButton.isSelected();
            toggleButton.setText(loggingEnabled ? "Logging: ON" : "Logging: OFF");
        });
        JLabel memLabel = new JLabel("Disable logging to reduce memory usage (last " + MAX_LOG_ENTRIES + " requests kept)");
        memLabel.setFont(memLabel.getFont().deriveFont(Font.ITALIC, 11f));
        memLabel.setForeground(Color.GRAY);

        JPanel controlBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        controlBar.add(toggleButton);
        controlBar.add(memLabel);

        uiComponent = new JPanel(new BorderLayout());
        uiComponent.add(controlBar, BorderLayout.NORTH);
        uiComponent.add(splitPane, BorderLayout.CENTER);

        // Show the request for the selected row in the viewer.
        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int row = table.getSelectedRow();
            if (row >= 0 && row < requestHistory.size()) {
                HttpRequest[] snapshot = requestHistory.toArray(new HttpRequest[0]);
                requestViewer.setRequest(snapshot[row]);
            }
        });
    }

    public void log(HttpRequest request, String mutation) {
        if (!loggingEnabled) return;

        SwingUtilities.invokeLater(() -> {
            // Roll off oldest entry when at capacity.
            if (requestHistory.size() >= MAX_LOG_ENTRIES) {
                requestHistory.pollFirst();
                tableModel.removeRow(0);
            }

            requestHistory.addLast(request);
            tableModel.addRow(new Object[]{
                    ++sequenceCounter,
                    request.method(),
                    request.url(),
                    mutation != null ? mutation : "-",
                    java.time.LocalTime.now().withNano(0).toString()
            });
        });
    }

    public void shutdown() {
        loggingEnabled = false;
        SwingUtilities.invokeLater(() -> {
            requestHistory.clear();
            tableModel.setRowCount(0);
        });
    }

    public Component getUiComponent() {
        return uiComponent;
    }
}
