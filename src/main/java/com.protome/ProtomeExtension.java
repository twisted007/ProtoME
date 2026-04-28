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

/**
 * ProtomeExtension — the Burp entry point and UI owner.
 *
 * This is the class Burp loads first. It implements BurpExtension, which is
 * the Montoya API's equivalent of a main() method — Burp calls initialize()
 * once when the extension loads, and this method is responsible for wiring
 * everything together:
 *   - Instantiating ProtoManager (schema logic) and RequestLogger (log tab UI)
 *   - Registering ProtomeHttpHandler so Burp knows to route all HTTP traffic through it
 *   - Building the Swing UI for the Settings, Logger, and Mutations tabs
 *
 * After initialize() returns, this class is essentially passive — it owns the
 * UI components and responds to user interactions (file picker, right-click menu,
 * copy buttons), but the actual request interception happens in ProtomeHttpHandler.
 *
 * UI framework note: Burp's UI is built on Java Swing. All UI work must happen
 * on the Event Dispatch Thread (EDT), which Burp handles for us during initialize().
 */
public class ProtomeExtension implements BurpExtension {
    private MontoyaApi api;
    private ProtoManager protoManager;
    private RequestLogger logger;

    // These are class-level fields (not local variables) because multiple methods
    // need to read and update them — the file picker populates the tree and text area,
    // and the right-click menu reads the tree's current selection.
    private JTextArea protoTextArea;
    private JTree messageTree;
    private DefaultMutableTreeNode treeRoot;
    private DefaultTreeModel treeModel;

    /**
     * Called once by Burp on extension load. This is the wiring point for the
     * whole extension — everything that needs to exist gets created here.
     */
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.api.extension().setName("ProtoME");

        // ProtoManager holds the loaded schema and does all serialization work.
        // RequestLogger owns the Logger tab UI and the log table.
        this.protoManager = new ProtoManager(api);
        this.logger = new RequestLogger(api);

        // Register our HTTP handler with Burp. From this point forward, Burp will
        // call ProtomeHttpHandler.handleHttpRequestToBeSent() for every outgoing request.
        api.http().registerHttpHandler(new ProtomeHttpHandler(api, protoManager, logger));

        // Register the blackbox context menu. This adds "Send to ProtoME (Blackbox)"
        // to the right-click menu everywhere Burp displays an HTTP request.
        api.userInterface().registerContextMenuItemsProvider(new BlackboxContextMenu(api));

        // Build the tabbed UI panel and register it as a top-level Burp Suite tab.
        JPanel mainPanel = new JPanel(new BorderLayout());
        JTabbedPane tabs = new JTabbedPane();
        tabs.add("Settings", buildSettingsTab());
        tabs.add("Logger", logger.getUiComponent());
        tabs.add("Mutations", buildMutationsTab());

        mainPanel.add(tabs);
        api.userInterface().registerSuiteTab("ProtoME", mainPanel);
        api.logging().logToOutput("ProtoME loaded.");
    }

    /**
     * Builds the Settings tab — the main configuration UI.
     *
     * Layout overview:
     *   TOP:    "Select .proto File" button + path label
     *   LEFT:   Tree view of all message types and their fields (collapsible)
     *   RIGHT:  Raw .proto source text (read-only, for reference)
     *
     * Right-clicking a message node in the tree opens a context menu with two
     * payload generation helpers: one that copies just the JSON body, and one
     * that copies a complete ready-to-paste Burp HTTP request with all the
     * required ProtoME headers pre-filled.
     */
    private JPanel buildSettingsTab() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // === TOP BAR: file picker ===
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        JButton browseButton = new JButton("Select .proto File");
        JLabel pathLabel = new JLabel("No file selected");
        topPanel.add(browseButton);
        topPanel.add(pathLabel);

        // === LEFT PANE: message tree ===
        // The tree is initially empty ("No file loaded"). After a file is picked,
        // updateProtoView() rebuilds it with one node per top-level message type,
        // and child nodes for each field showing its type and name.
        treeRoot = new DefaultMutableTreeNode("No file loaded");
        treeModel = new DefaultTreeModel(treeRoot);
        messageTree = new JTree(treeModel);
        messageTree.setRootVisible(true);
        messageTree.setShowsRootHandles(true);
        JScrollPane treeScrollPane = new JScrollPane(messageTree);
        treeScrollPane.setPreferredSize(new Dimension(280, 0));
        treeScrollPane.setBorder(BorderFactory.createTitledBorder("Messages"));

        // === RIGHT PANE: raw proto source ===
        // Read-only display of the .proto file text — useful for cross-referencing
        // the tree view with the actual schema definition.
        protoTextArea = new JTextArea();
        protoTextArea.setEditable(false);
        protoTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        protoTextArea.setText("Load a .proto file to view its contents here.");
        JScrollPane textScrollPane = new JScrollPane(protoTextArea);
        textScrollPane.setBorder(BorderFactory.createTitledBorder("Proto Source"));

        // A JSplitPane lets the user drag the divider to resize the two panes.
        // resizeWeight(0.25) means the left pane gets 25% of any extra space when
        // the window is resized; the right pane gets the remaining 75%.
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treeScrollPane, textScrollPane);
        splitPane.setDividerLocation(280);
        splitPane.setResizeWeight(0.25);

        // === CONTEXT MENU: right-click on a message node ===
        JPopupMenu contextMenu = new JPopupMenu();
        JMenuItem buildRequestItem = new JMenuItem("Build Request");
        JMenuItem copyFullRequestItem = new JMenuItem("Copy as Full Burp Request");
        contextMenu.add(buildRequestItem);
        contextMenu.add(copyFullRequestItem);

        // "Build Request" — generates a JSON body with dummy values and copies it.
        // Useful for quickly getting a template to paste into Repeater.
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

        // "Copy as Full Burp Request" — wraps the JSON body in a complete HTTP request
        // string with all the ProtoME headers pre-filled. Paste directly into Repeater.
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

        // We listen for both mousePressed and mouseReleased because the OS-level
        // trigger for a right-click popup differs between platforms (Windows fires
        // on release; some Linux environments fire on press).
        messageTree.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e)  { maybeShowPopup(e); }
            @Override public void mouseReleased(MouseEvent e) { maybeShowPopup(e); }

            private void maybeShowPopup(MouseEvent e) {
                if (!e.isPopupTrigger()) return;
                TreePath path = messageTree.getPathForLocation(e.getX(), e.getY());
                if (path == null) return;
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
                // Only show the menu when the user right-clicks an actual message node,
                // not a field node (which is just a plain String, not a MessageNodeData).
                if (!(node.getUserObject() instanceof MessageNodeData)) return;
                messageTree.setSelectionPath(path);
                contextMenu.show(messageTree, e.getX(), e.getY());
            }
        });

        // When the user picks a file, load it into ProtoManager and refresh the UI.
        browseButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(panel) == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                pathLabel.setText(selectedFile.getAbsolutePath());
                try {
                    protoManager.loadProto(selectedFile);  // compile + parse
                    updateProtoView(selectedFile);          // refresh tree and text area
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

    /**
     * Builds the Mutations tab — a reference table of available fuzzing strategies.
     *
     * This tab is purely informational UI. The actual mutation logic lives in
     * ProtoMutator. The table gives each strategy a name and plain-English description,
     * and the buttons make it easy to copy the correct header value for use in
     * Repeater (single strategy) or as a payload list for Intruder (all strategies).
     */
    private JPanel buildMutationsTab() {
        String[][] strategies = {
            {"wire-type-flip",  "Flips wire types in all field tags (VARINT↔LEN, I64↔I32). Parser receives the wrong type for every field."},
            {"varint-overflow", "Pads all VARINT field values to 11 bytes, exceeding the 10-byte spec maximum."},
            {"length-bomb",     "Replaces LEN field lengths with 2 147 483 647, forcing a 2 GB allocation attempt."},
            {"duplicate-field", "Appends the entire serialized message to itself so every field appears twice."},
            {"unknown-field",   "Appends fields 10000–10003 (all wire types) that won’t exist in any real schema."},
        };

        String[] columns = {"Strategy", "Description"};
        // isCellEditable returning false makes the table read-only — clicks select
        // rows but don't open an editor.
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

        // "Copy Selected Header" outputs the ready-to-paste header value for the
        // selected strategy, e.g. "protome-mutate: wire-type-flip".
        JButton copyHeader = new JButton("Copy Selected Header");
        copyHeader.setEnabled(false);
        copyHeader.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row < 0) return;
            String strategy = (String) model.getValueAt(row, 0);
            copyToClipboard("protome-mutate: " + strategy);
        });

        // "Copy All" outputs every strategy name on its own line — formatted for
        // pasting directly into Burp Intruder as a simple list payload.
        JButton copyAll = new JButton("Copy All (Intruder Payload List)");
        copyAll.addActionListener(e -> {
            StringBuilder sb = new StringBuilder();
            for (String[] row : strategies) sb.append(row[0]).append("\n");
            copyToClipboard(sb.toString().trim());
        });

        // Keep the "Copy Selected Header" button greyed out until a row is selected.
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

    /**
     * Refreshes both the raw source text area and the message tree after a new
     * .proto file is loaded. Called every time the user picks a file.
     */
    private void updateProtoView(File protoFile) {
        // Show the raw .proto source on the right so the user can cross-reference
        // the tree structure with the actual field definitions.
        try {
            String content = new String(Files.readAllBytes(protoFile.toPath()), StandardCharsets.UTF_8);
            protoTextArea.setText(content);
            protoTextArea.setCaretPosition(0); // scroll back to top
        } catch (Exception e) {
            protoTextArea.setText("Error reading file: " + e.getMessage());
        }

        // Rebuild the message tree from scratch.
        treeRoot.removeAllChildren();
        treeRoot.setUserObject(protoFile.getName());

        // messageDescriptors contains both short and full names for each message, so
        // we'd get duplicates if we iterated it directly. We deduplicate by full name
        // using a LinkedHashMap (which preserves insertion order) and only keep
        // top-level messages — nested types will be shown as children of their parent.
        LinkedHashMap<String, Descriptors.Descriptor> topLevel = new LinkedHashMap<>();
        for (Descriptors.Descriptor d : protoManager.getMessageDescriptors().values()) {
            if (d.getContainingType() == null) { // null means it's not nested inside another message
                topLevel.put(d.getFullName(), d);
            }
        }

        for (Descriptors.Descriptor msgDesc : topLevel.values()) {
            DefaultMutableTreeNode msgNode = new DefaultMutableTreeNode(
                new MessageNodeData(msgDesc.getName(), msgDesc)
            );
            addFieldNodes(msgNode, msgDesc); // attach field children
            treeRoot.add(msgNode);
        }

        // treeModel.reload() tells Swing that the tree data changed and it needs to repaint.
        treeModel.reload();

        // Expand every row so all messages and fields are visible by default.
        for (int i = 0; i < messageTree.getRowCount(); i++) {
            messageTree.expandRow(i);
        }
    }

    // Adds one child node per field to a message node in the tree.
    // Field nodes are plain strings (not MessageNodeData), so the right-click
    // menu won't appear on them — only message nodes are actionable.
    private void addFieldNodes(DefaultMutableTreeNode parent, Descriptors.Descriptor descriptor) {
        for (Descriptors.FieldDescriptor field : descriptor.getFields()) {
            String label = (field.isRepeated() ? "repeated " : "") + getTypeName(field) + "  " + field.getName();
            parent.add(new DefaultMutableTreeNode(label));
        }
    }

    // Translates a FieldDescriptor's type enum into the .proto keyword string
    // (e.g. Type.STRING -> "string", Type.MESSAGE -> the nested message's name).
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

    /**
     * Produces a complete HTTP request string ready to paste into Burp Repeater.
     * Content-Length is calculated from the JSON bytes (not characters) because
     * multi-byte UTF-8 characters would cause a mismatch otherwise.
     */
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

    // Writes text to the OS clipboard using Java's AWT Toolkit.
    private void copyToClipboard(String text) {
        StringSelection selection = new StringSelection(text);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
    }

    // Returns the Descriptor for the currently selected tree node, or null if
    // the selection is empty or is a field node rather than a message node.
    private Descriptors.Descriptor getSelectedDescriptor() {
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) messageTree.getLastSelectedPathComponent();
        if (node == null || !(node.getUserObject() instanceof MessageNodeData)) return null;
        return ((MessageNodeData) node.getUserObject()).descriptor;
    }

    /**
     * Wrapper that pairs a display name with the live Descriptor object for a
     * message type. Used as the user object for message nodes in the tree so that
     * right-click actions can retrieve the Descriptor directly from the selected node
     * without doing a second map lookup. toString() controls what text appears in the tree.
     */
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
