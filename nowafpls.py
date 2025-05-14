# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory, IHttpListener, IRequestInfo, IContextMenuInvocation
from javax.swing import JMenuItem, JLabel, JTextField, JOptionPane, JPanel, JFrame
import javax.swing as swing
from java.util import ArrayList
from java.io import ByteArrayOutputStream
import re
import random
import string

class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("burp-nowafpls")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)

    def createMenuItems(self, invocation):
        self.context = invocation
        menu_list = ArrayList()
        if self.context.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            menu_list.add(JMenuItem("Insert Junk Data Size", actionPerformed=self.insert_random_data))
            menu_list.add(JMenuItem("Insert double Content-Length", actionPerformed=self.insert_double_content_length))
            menu_list.add(JMenuItem("Confuse WAF ignore CL", actionPerformed=self.confuse_waf_ignore_cl))
            menu_list.add(JMenuItem("Confuse WAF ignore TE", actionPerformed=self.confuse_waf_ignore_te))
            menu_list.add(JMenuItem("Chunk body in X blocks", actionPerformed=self.chunk_body_x_blocks))
            menu_list.add(JMenuItem("Chunk body in 2 blocks (invalid)", actionPerformed=self.chunk_body_2_blocks))
        return menu_list

    def generate_random_string(self, length, charset=None):
        if charset is None:
            charset = string.ascii_letters + string.digits + "-_"
        return ''.join(random.choice(charset) for _ in range(length))

    def generate_random_param(self):
        prefixes = ['id']
        suffix = self.generate_random_string(random.randint(4, 8))
        return random.choice(prefixes) + "_" + suffix

    def generate_varied_content(self, size):
        chunks = []
        remaining_size = size
        
        while remaining_size > 0:
            chunk_size = min(random.randint(8, 32), remaining_size)
            chunk_type = random.randint(1, 4)
            
            if chunk_type == 1:
                chunk = self.generate_random_string(chunk_size)
            elif chunk_type == 2:
                chunk = self.generate_random_string(chunk_size, string.hexdigits)
            elif chunk_type == 3:
                chunk = self.generate_random_string(chunk_size, string.ascii_letters + string.digits + "+/")
            else:
                chunk = self.generate_random_string(chunk_size, string.ascii_letters + string.digits + "-._~")
            
            chunks.append(chunk)
            remaining_size -= chunk_size
        
        return ''.join(chunks)

    def insert_random_data(self, event):
        message = self.context.getSelectedMessages()[0]
        request = message.getRequest()
        selection_bounds = self.context.getSelectionBounds()
        insertion_point = selection_bounds[0] if selection_bounds else len(request)

        options_panel = JPanel()
        options_panel.setLayout(swing.BoxLayout(options_panel, swing.BoxLayout.Y_AXIS))

        junk_sizes_kb = [8, 16, 32, 64, 128, 1024, "Custom"]
        dropdown = swing.JComboBox([str(size) + " KB" if isinstance(size, int) else size for size in junk_sizes_kb])
        
        custom_size_field = JTextField(10)
        custom_size_label = JLabel("Custom size (bytes):")

        custom_size_field.setVisible(dropdown.getSelectedItem() == "Custom")
        custom_size_label.setVisible(dropdown.getSelectedItem() == "Custom")

        options_panel.add(dropdown)
        options_panel.add(custom_size_label)
        options_panel.add(custom_size_field)

        def update_custom_field_visibility(event):
            is_custom_selected = dropdown.getSelectedItem() == "Custom"
            custom_size_label.setVisible(is_custom_selected)
            custom_size_field.setVisible(is_custom_selected)
            if is_custom_selected:
                custom_size_field.requestFocus()
            swing.SwingUtilities.getWindowAncestor(options_panel).pack()

        dropdown.addActionListener(update_custom_field_visibility)

        frame = JFrame()
        dialog = JOptionPane.showConfirmDialog(frame, options_panel, "Select Junk Data Size", 
                                             JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)
        
        if dialog == JOptionPane.OK_OPTION:
            selected_size = dropdown.getSelectedItem()
            if selected_size == "Custom":
                try:
                    size_bytes = int(custom_size_field.getText())
                except ValueError:
                    JOptionPane.showMessageDialog(None, "Please enter a valid number for custom size.")
                    return
            else:
                size_bytes = int(selected_size.split()[0]) * 1024

            content_type = self._helpers.analyzeRequest(message).getContentType()
            
            if content_type == IRequestInfo.CONTENT_TYPE_URL_ENCODED:
                param_name = self.generate_random_param()
                junk_data = param_name + "=" + self.generate_varied_content(size_bytes - len(param_name) - 1) + "&"
            
            elif content_type == IRequestInfo.CONTENT_TYPE_XML:
                comment_content = self.generate_varied_content(size_bytes - 7)
                junk_data = "<!--{}-->".format(comment_content)
            
            elif content_type == IRequestInfo.CONTENT_TYPE_JSON:
                param_name = self.generate_random_param()
                junk_data = '"{}":"{}",'.format(param_name, self.generate_varied_content(size_bytes - len(param_name) - 5))
            
            elif content_type == IRequestInfo.CONTENT_TYPE_MULTIPART:
                junk_data = self.create_multipart_junk(request, size_bytes)
            
            else:
                return

            baos = ByteArrayOutputStream()
            baos.write(request[:insertion_point])
            baos.write(junk_data.encode('utf-8'))
            baos.write(request[insertion_point:])
            message.setRequest(baos.toByteArray())

    def create_multipart_junk(self, request, size):
        request_string = self._helpers.bytesToString(request)
        boundary = re.search(r'boundary=([\w-]+)', request_string)
        if not boundary:
            return ""

        boundary = boundary.group(1)
        junk_field_name = self.generate_random_param()
        
        multipart_structure = (
            "--{0}\r\n"
            "Content-Disposition: form-data; name=\"{1}\"\r\n\r\n"
            "{2}\r\n"
        )
        
        structure_size = len(multipart_structure.format(boundary, junk_field_name, ""))
        junk_data = self.generate_varied_content(size - structure_size)
        
        multipart_junk = multipart_structure.format(boundary, junk_field_name, junk_data)
        return multipart_junk

    def insert_double_content_length(self, event):
        message = self.context.getSelectedMessages()[0]
        request = message.getRequest()
        selection_bounds = self.context.getSelectionBounds()
        if not selection_bounds:
            JOptionPane.showMessageDialog(None, "No cursor position found.")
            return
        cursor_pos = selection_bounds[0]
        # Convert bytes to string for easier manipulation
        request_str = self._helpers.bytesToString(request)
        # Split headers and body
        split_seq = '\r\n\r\n'
        split_index = request_str.find(split_seq)
        if split_index == -1:
            JOptionPane.showMessageDialog(None, "Could not find end of headers.")
            return
        headers_part = request_str[:split_index]
        body_part = request_str[split_index+len(split_seq):]
        # Calculer la position du curseur dans le body
        # On doit convertir la position du curseur (dans les bytes) en position dans le body
        # Pour cela, on compte le nombre de bytes jusqu'au début du body
        headers_bytes = self._helpers.stringToBytes(headers_part + split_seq)
        body_start_offset = len(headers_bytes)
        if cursor_pos < body_start_offset:
            JOptionPane.showMessageDialog(None, "Cursor must be in the body of the request.")
            return
        content_length_value = cursor_pos - body_start_offset
        # Préparer le nouvel en-tête
        new_header = "Content-Length: {}".format(content_length_value)
        # Chercher la position du Content-Length original
        lines = headers_part.split('\r\n')
        insert_index = None
        for i, line in enumerate(lines):
            if line.lower().startswith('content-length:'):
                insert_index = i
                break
        if insert_index is None:
            # S'il n'y a pas de Content-Length, on l'ajoute à la fin des headers
            lines.append(new_header)
        else:
            lines.insert(insert_index, new_header)
        # Reconstruire la requête
        new_headers = '\r\n'.join(lines)
        new_request_str = new_headers + split_seq + body_part
        # Remplacer la requête
        message.setRequest(self._helpers.stringToBytes(new_request_str))

    def confuse_waf_ignore_te(self, event):
        message = self.context.getSelectedMessages()[0]
        request = message.getRequest()
        request_str = self._helpers.bytesToString(request)
        split_seq = '\r\n\r\n'
        split_index = request_str.find(split_seq)
        if split_index == -1:
            JOptionPane.showMessageDialog(None, "Could not find end of headers.")
            return
        headers_part = request_str[:split_index]
        body_part = request_str[split_index+len(split_seq):]
        # Préparer le nouvel en-tête
        new_header = "Transfer-Encoding: chunked"
        lines = headers_part.split('\r\n')
        insert_index = None
        cl_index = None
        for i, line in enumerate(lines):
            if line.lower().startswith('content-length:'):
                insert_index = i
                cl_index = i
                break
        if insert_index is None:
            lines.append(new_header)
        else:
            lines.insert(insert_index, new_header)
        # Récupérer la position du curseur
        selection_bounds = self.context.getSelectionBounds()
        if not selection_bounds:
            JOptionPane.showMessageDialog(None, "No cursor position found.")
            return
        cursor_pos = selection_bounds[0]
        # Calculer l'offset du début du body
        headers_bytes = self._helpers.stringToBytes(headers_part + split_seq)
        body_start_offset = len(headers_bytes)
        if cursor_pos < body_start_offset:
            JOptionPane.showMessageDialog(None, "Cursor must be in the body of the request.")
            return
        # Découper le body
        chunk_len = cursor_pos - body_start_offset
        body_to_chunk = body_part[:chunk_len]
        body_after_cursor = body_part[chunk_len:]
        # Transformer body_to_chunk en chunked
        def to_chunked(data, chunk_size=8):
            out = []
            i = 0
            while i < len(data):
                chunk = data[i:i+chunk_size]
                out.append("{:x}\r\n".format(len(chunk)))
                out.append(chunk)
                out.append("\r\n")
                i += chunk_size
            out.append("0\r\n\r\n")
            return ''.join(out)
        chunked_body = to_chunked(body_to_chunk)
        # Reconstituer le body : [chunked][reste]
        new_body = chunked_body + body_after_cursor
        # Mettre à jour le Content-Length pour qu'il englobe tout le body
        new_content_length = len(self._helpers.stringToBytes(new_body))
        if cl_index is not None:
            # Remplacer l'ancien Content-Length
            for i, line in enumerate(lines):
                if line.lower().startswith('content-length:'):
                    lines[i] = "Content-Length: {}".format(new_content_length)
        else:
            # Ajouter Content-Length si absent
            lines.append("Content-Length: {}".format(new_content_length))
        new_headers = '\r\n'.join(lines)
        new_request_str = new_headers + split_seq + new_body
        message.setRequest(self._helpers.stringToBytes(new_request_str))

    def confuse_waf_ignore_cl(self, event):
        message = self.context.getSelectedMessages()[0]
        request = message.getRequest()
        request_str = self._helpers.bytesToString(request)
        split_seq = '\r\n\r\n'
        split_index = request_str.find(split_seq)
        if split_index == -1:
            JOptionPane.showMessageDialog(None, "Could not find end of headers.")
            return
        headers_part = request_str[:split_index]
        body_part = request_str[split_index+len(split_seq):]
        # Préparer le nouvel en-tête
        new_header = "Transfer-Encoding: chunked"
        lines = headers_part.split('\r\n')
        insert_index = None
        cl_index = None
        for i, line in enumerate(lines):
            if line.lower().startswith('content-length:'):
                insert_index = i
                cl_index = i
                break
        if insert_index is None:
            lines.append(new_header)
        else:
            lines.insert(insert_index, new_header)
        # Récupérer la position du curseur
        selection_bounds = self.context.getSelectionBounds()
        if not selection_bounds:
            JOptionPane.showMessageDialog(None, "No cursor position found.")
            return
        cursor_pos = selection_bounds[0]
        # Calculer l'offset du début du body
        headers_bytes = self._helpers.stringToBytes(headers_part + split_seq)
        body_start_offset = len(headers_bytes)
        if cursor_pos < body_start_offset:
            JOptionPane.showMessageDialog(None, "Cursor must be in the body of the request.")
            return
        # Découper le body
        chunk_len = cursor_pos - body_start_offset
        body_to_chunk = body_part[:chunk_len]
        body_after_cursor = body_part[chunk_len:]
        # Créer deux chunks : un pour le début, un pour le reste
        chunks = []
        if body_to_chunk:
            chunks.append("{:x}\r\n".format(len(body_to_chunk)) + body_to_chunk + "\r\n")
        if body_after_cursor:
            chunks.append("{:x}\r\n".format(len(body_after_cursor)) + body_after_cursor + "\r\n")
        chunks.append("0\r\n\r\n")  # chunk de fin
        new_body = ''.join(chunks)
        # Mettre à jour le Content-Length pour qu'il corresponde à la portion chunkée uniquement (avant le curseur)
        new_content_length = len(self._helpers.stringToBytes(body_to_chunk))
        if cl_index is not None:
            for i, line in enumerate(lines):
                if line.lower().startswith('content-length:'):
                    lines[i] = "Content-Length: {}".format(new_content_length+3)
        else:
            lines.append("Content-Length: {}".format(new_content_length+3))
        new_headers = '\r\n'.join(lines)
        new_request_str = new_headers + split_seq + new_body
        message.setRequest(self._helpers.stringToBytes(new_request_str))

    def chunk_body_x_blocks(self, event):
        message = self.context.getSelectedMessages()[0]
        request = message.getRequest()
        request_str = self._helpers.bytesToString(request)
        split_seq = '\r\n\r\n'
        split_index = request_str.find(split_seq)
        if split_index == -1:
            JOptionPane.showMessageDialog(None, "Could not find end of headers.")
            return
        headers_part = request_str[:split_index]
        body_part = request_str[split_index+len(split_seq):]
        # Demander à l'utilisateur le nombre de chunks
        x_str = JOptionPane.showInputDialog(None, "How many chunks? (X)", "Chunk body in X blocks", JOptionPane.QUESTION_MESSAGE)
        try:
            x = int(x_str)
            if x < 1:
                raise ValueError
            if x > len(body_part):
                JOptionPane.showMessageDialog(None, "You can't create more blocks than there are characters in the body.")
                return
        except Exception:
            JOptionPane.showMessageDialog(None, "Please enter a valid positive integer.")
            return
        # Chunker le body en X blocs
        chunk_size = len(body_part) // x
        remainder = len(body_part) % x
        chunks = []
        start = 0
        for i in range(x):
            end = start + chunk_size + (1 if i < remainder else 0)
            chunk = body_part[start:end]
            if chunk:
                chunks.append("{:x}\r\n".format(len(chunk)) + chunk + "\r\n")
            start = end
        chunks.append("0\r\n\r\n")
        new_body = ''.join(chunks)
        # Ajouter/insérer Transfer-Encoding: chunked si absent et supprimer Content-Length
        lines = headers_part.split('\r\n')
        lines = [line for line in lines if not line.lower().startswith('content-length:')]
        te_present = any(line.lower().startswith('transfer-encoding:') for line in lines)
        if not te_present:
            lines.append("Transfer-Encoding: chunked")
        new_headers = '\r\n'.join(lines)
        new_request_str = new_headers + split_seq + new_body
        message.setRequest(self._helpers.stringToBytes(new_request_str))

    def chunk_body_2_blocks(self, event):
        message = self.context.getSelectedMessages()[0]
        request = message.getRequest()
        request_str = self._helpers.bytesToString(request)
        split_seq = '\r\n\r\n'
        split_index = request_str.find(split_seq)
        if split_index == -1:
            JOptionPane.showMessageDialog(None, "Could not find end of headers.")
            return
        headers_part = request_str[:split_index]
        body_part = request_str[split_index+len(split_seq):]
        if len(body_part) < 2:
            JOptionPane.showMessageDialog(None, "Body too short to split in 2 blocks.")
            return
        # Découper en 2 chunks
        mid = len(body_part) // 2
        chunk1 = body_part[:mid]
        chunk2 = body_part[mid:]
        chunks = []
        if chunk1:
            chunks.append("{:x}\r\n".format(len(chunk1)) + chunk1 + "\r\n")
        if chunk2:
            chunks.append("{:x}\r\n".format(len(chunk2)-(len(chunk2)/2)) + chunk2 + "\r\n")
        chunks.append("0\r\n\r\n")
        new_body = ''.join(chunks)
        # Supprimer Content-Length et ajouter Transfer-Encoding: chunked si absent
        lines = headers_part.split('\r\n')
        lines = [line for line in lines if not line.lower().startswith('content-length:')]
        te_present = any(line.lower().startswith('transfer-encoding:') for line in lines)
        if not te_present:
            lines.append("Transfer-Encoding: chunked")
        new_headers = '\r\n'.join(lines)
        new_request_str = new_headers + split_seq + new_body
        message.setRequest(self._helpers.stringToBytes(new_request_str))
