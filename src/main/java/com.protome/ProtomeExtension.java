package com.protome;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.google.protobuf.Descriptors;

import javax.swing.*;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.event.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;

public class ProtomeExtension implements BurpExtension {
    private MontoyaApi api;
    private ProtoManager protoManager;
    private RequestLogger logger;

    private JTextArea protoTextArea;
    private JTree messageTree;
    private DefaultMutableTreeNode treeRoot;
    private DefaultTreeModel treeModel;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.api.extension().setName("Protome");
        this.protoManager = new ProtoManager(api);
        this.logger = new RequestLogger(api);

        api.http().registerHttpHandler(new ProtomeHttpHandler(api, protoManager, logger));

        JPanel mainPanel = new JPanel(new BorderLayout());
        JTabbedPane tabs = new JTabbedPane();

        tabs.add("Settings", buildSettingsTab());
        tabs.add("Logger", logger.getUiComponent());
        tabs.add("Mutations", buildMutationsTab());

        mainPanel.add(tabs);
        api.userInterface().registerSuiteTab("Protome", mainPanel);
        api.logging().logToOutput("Protome loaded.");
    }

    private JPanel buildSettingsTab() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // --- Top: file browse controls ---
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        JButton browseButton = new JButton("Select .proto File");
        JLabel pathLabel = new JLabel("No file selected");
        topPanel.add(browseButton);
        topPanel.add(pathLabel);

        // --- Left: message tree ---
        treeRoot = new DefaultMutableTreeNode("No file loaded");
        treeModel = new DefaultTreeModel(treeRoot);
        messageTree = new JTree(treeModel);
        messageTree.setRootVisible(true);
        messageTree.setShowsRootHandles(true);
        JScrollPane treeScrollPane = new JScrollPane(messageTree);
        treeScrollPane.setPreferredSize(new Dimension(280, 0));
        treeScrollPane.setBorder(BorderFactory.createTitledBorder("Messages"));

        // --- Right: raw proto source ---
        protoTextArea = new JTextArea();
        protoTextArea.setEditable(false);
        protoTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        protoTextArea.setText("Load a .proto file to view its contents here.");
        JScrollPane textScrollPane = new JScrollPane(protoTextArea);
        textScrollPane.setBorder(BorderFactory.createTitledBorder("Proto Source"));

        // --- Split pane ---
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treeScrollPane, textScrollPane);
        splitPane.setDividerLocation(280);
        splitPane.setResizeWeight(0.25);

        // --- Context menu ---
        JPopupMenu contextMenu = new JPopupMenu();
        JMenuItem buildRequestItem = new JMenuItem("Build Request");
        JMenuItem copyFullRequestItem = new JMenuItem("Copy as Full Burp Request");
        contextMenu.add(buildRequestItem);
        contextMenu.add(copyFullRequestItem);

        buildRequestItem.addActionListener(e -> {
            Descriptors.Descriptor desc = getSelectedDescriptor();
            if (desc == null) return;
            try {
                String json = protoManager.generateDummyJson(desc);
                copyToClipboard(json);
                JOptionPane.showMessageDialog(panel,
                    "JSON body for '" + desc.getName() + "' copied to clipboard.");
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "Error generating JSON: " + ex.getMessage());
            }
        });

        copyFullRequestItem.addActionListener(e -> {
            Descriptors.Descriptor desc = getSelectedDescriptor();
            if (desc == null) return;
            try {
                String json = protoManager.generateDummyJson(desc);
                copyToClipboard(buildFullBurpRequest(desc, json));
                JOptionPane.showMessageDialog(panel,
                    "Full Burp request for '" + desc.getName() + "' copied to clipboard.");
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "Error generating request: " + ex.getMessage());
            }
        });

        messageTree.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e)  { maybeShowPopup(e); }
            @Override public void mouseReleased(MouseEvent e) { maybeShowPopup(e); }

            private void maybeShowPopup(MouseEvent e) {
                if (!e.isPopupTrigger()) return;
                TreePath path = messageTree.getPathForLocation(e.getX(), e.getY());
                if (path == null) return;
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
                if (!(node.getUserObject() instanceof MessageNodeData)) return;
                messageTree.setSelectionPath(path);
                contextMenu.show(messageTree, e.getX(), e.getY());
            }
        });

        browseButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(panel) == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                pathLabel.setText(selectedFile.getAbsolutePath());
                try {
                    protoManager.loadProto(selectedFile);
                    updateProtoView(selectedFile);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(panel, "Error loading .proto: " + ex.getMessage());
                    api.logging().logToError(ex);
                }
            }
        });

        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(splitPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildMutationsTab() {
        String[][] strategies = {
            {"wire-type-flip",  "Flips wire types in all field tags (VARINT\u2194LEN, I64\u2194I32). Parser receives the wrong type for every field."},
            {"varint-overflow", "Pads all VARINT field values to 11 bytes, exceeding the 10-byte spec maximum."},
            {"length-bomb",     "Replaces LEN field lengths with 2 147 483 647, forcing a 2 GB allocation attempt."},
            {"duplicate-field", "Appends the entire serialized message to itself so every field appears twice."},
            {"unknown-field",   "Appends fields 10000\u201310003 (all wire types) that won\u2019t exist in any real schema."},
        };

        String[] columns = {"Strategy", "Description"};
        javax.swing.table.DefaultTableModel model = new javax.swing.table.DefaultTableModel(columns, 0) {
            @Override public boolean isCellEditable(int row, int col) { return false; }
        };
        for (String[] row : strategies) model.addRow(row);

        JTable table = new JTable(model);
        table.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        table.getColumnModel().getColumn(0).setPreferredWidth(140);
        table.getColumnModel().getColumn(0).setMaxWidth(200);
        table.getColumnModel().getColumn(1).setPreferredWidth(600);
        table.setRowHeight(22);

        JButton copyHeader = new JButton("Copy Selected Header");
        copyHeader.setEnabled(false);
        copyHeader.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row < 0) return;
            String strategy = (String) model.getValueAt(row, 0);
            copyToClipboard("protome-mutate: " + strategy);
        });

        JButton copyAll = new JButton("Copy All (Intruder Payload List)");
        copyAll.addActionListener(e -> {
            StringBuilder sb = new StringBuilder();
            for (String[] row : strategies) sb.append(row[0]).append("\n");
            copyToClipboard(sb.toString().trim());
        });

        table.getSelectionModel().addListSelectionListener(e -> copyHeader.setEnabled(table.getSelectedRow() >= 0));

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        buttons.add(copyHeader);
        buttons.add(copyAll);

        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.SOUTH);
        return panel;
    }

    private void updateProtoView(File protoFile) {
        // Update raw source text area
        try {
            String content = new String(Files.readAllBytes(protoFile.toPath()), StandardCharsets.UTF_8);
            protoTextArea.setText(content);
            protoTextArea.setCaretPosition(0);
        } catch (Exception e) {
            protoTextArea.setText("Error reading file: " + e.getMessage());
        }

        // Rebuild message tree — deduplicate by full name, top-level only
        treeRoot.removeAllChildren();
        treeRoot.setUserObject(protoFile.getName());

        LinkedHashMap<String, Descriptors.Descriptor> topLevel = new LinkedHashMap<>();
        for (Descriptors.Descriptor d : protoManager.getMessageDescriptors().values()) {
            if (d.getContainingType() == null) {
                topLevel.put(d.getFullName(), d);
            }
        }

        for (Descriptors.Descriptor msgDesc : topLevel.values()) {
            DefaultMutableTreeNode msgNode = new DefaultMutableTreeNode(
                new MessageNodeData(msgDesc.getName(), msgDesc)
            );
            addFieldNodes(msgNode, msgDesc);
            treeRoot.add(msgNode);
        }

        treeModel.reload();

        // Expand all rows
        for (int i = 0; i < messageTree.getRowCount(); i++) {
            messageTree.expandRow(i);
        }
    }

    private void addFieldNodes(DefaultMutableTreeNode parent, Descriptors.Descriptor descriptor) {
        for (Descriptors.FieldDescriptor field : descriptor.getFields()) {
            String label = (field.isRepeated() ? "repeated " : "") + getTypeName(field) + "  " + field.getName();
            parent.add(new DefaultMutableTreeNode(label));
        }
    }

    private String getTypeName(Descriptors.FieldDescriptor field) {
        switch (field.getType()) {
            case MESSAGE:  return field.getMessageType().getName();
            case ENUM:     return field.getEnumType().getName();
            case STRING:   return "string";
            case BOOL:     return "bool";
            case INT32:    return "int32";
            case INT64:    return "int64";
            case UINT32:   return "uint32";
            case UINT64:   return "uint64";
            case SINT32:   return "sint32";
            case SINT64:   return "sint64";
            case FIXED32:  return "fixed32";
            case FIXED64:  return "fixed64";
            case SFIXED32: return "sfixed32";
            case SFIXED64: return "sfixed64";
            case FLOAT:    return "float";
            case DOUBLE:   return "double";
            case BYTES:    return "bytes";
            default:       return field.getType().name().toLowerCase();
        }
    }

    private String buildFullBurpRequest(Descriptors.Descriptor desc, String json) {
        int contentLength = json.getBytes(StandardCharsets.UTF_8).length;
        return "POST /api/endpoint HTTP/1.1\r\n" +
               "Host: target.com\r\n" +
               "Content-Type: application/json\r\n" +
               "protome: true\r\n" +
               "protome-type: " + desc.getFullName() + "\r\n" +
               "Content-Length: " + contentLength + "\r\n" +
               "\r\n" +
               json;
    }

    private void copyToClipboard(String text) {
        StringSelection selection = new StringSelection(text);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
    }

    private Descriptors.Descriptor getSelectedDescriptor() {
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) messageTree.getLastSelectedPathComponent();
        if (node == null || !(node.getUserObject() instanceof MessageNodeData)) return null;
        return ((MessageNodeData) node.getUserObject()).descriptor;
    }

    static class MessageNodeData {
        final String displayName;
        final Descriptors.Descriptor descriptor;

        MessageNodeData(String displayName, Descriptors.Descriptor descriptor) {
            this.displayName = displayName;
            this.descriptor = descriptor;
        }

        @Override
        public String toString() {
            return displayName;
        }
    }
}
