"""Interfaz gráfica para encriptar y desencriptar mensajes con RSA."""

import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from rsa_decrypt import DecryptionResult, decrypt
from rsa_encrypt import EncryptionResult, encrypt
from rsa_math import ValidationError, modular_power_trace


class RSAApp(tk.Tk):
    """Aplicación de escritorio que comparte entradas con ambas operaciones."""

    def __init__(self) -> None:
        super().__init__()
        self.title("MM2015 · Proyecto de criptografía RSA")
        self.geometry("1040x780")
        self.minsize(850, 650)

        self.p = tk.StringVar()
        self.q = tk.StringVar()
        self.e = tk.StringVar()
        self.ciphertext = tk.StringVar()
        self.length = tk.StringVar()
        self.output_length = tk.StringVar()
        self.status = tk.StringVar(value="Ingrese un mensaje y los parámetros para encriptar.")
        self.summary = tk.StringVar(value="Los resultados se mostrarán aquí.")
        self.decryption_status = tk.StringVar(
            value="Ingrese C, L y los parámetros para desencriptar."
        )
        self.decryption_summary = tk.StringVar(value="Los resultados se mostrarán aquí.")
        self.latest_result: EncryptionResult | None = None
        self.latest_decryption_result: DecryptionResult | None = None

        self._configure_style()
        self._build_window()

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("TFrame", background="#f4f7fb")
        style.configure("TLabel", background="#f4f7fb", foreground="#1a2638")
        style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"), foreground="#174b85")
        style.configure("Help.TLabel", font=("Segoe UI", 10), foreground="#526176")
        style.configure("Status.TLabel", font=("Segoe UI", 10, "bold"), foreground="#174b85")
        style.configure("TLabelframe", background="#f4f7fb")
        style.configure("TLabelframe.Label", background="#f4f7fb", font=("Segoe UI", 11, "bold"))
        style.configure("TButton", font=("Segoe UI", 10), padding=7)
        style.configure("TNotebook", background="#f4f7fb")
        style.configure("TNotebook.Tab", font=("Segoe UI", 10), padding=(15, 7))
        style.configure("Treeview", font=("Consolas", 10), rowheight=26)
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

    def _build_window(self) -> None:
        self.configure(background="#f4f7fb")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        shell = ttk.Frame(self, padding=16)
        shell.grid(sticky="nsew")
        shell.columnconfigure(0, weight=1)
        shell.rowconfigure(2, weight=1)

        ttk.Label(shell, text="Criptografía RSA", style="Title.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(
            shell,
            text="MM2015 · ASCII imprimible · dos caracteres por bloque",
            style="Help.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(0, 12))

        self.tabs = ttk.Notebook(shell)
        self.tabs.grid(row=2, column=0, sticky="nsew")
        self.encryption_tab = ttk.Frame(self.tabs, padding=12)
        self.decryption_tab = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(self.encryption_tab, text="Encriptar · parte 1")
        self.tabs.add(self.decryption_tab, text="Desencriptar · parte 2")
        self._build_encryption_tab()
        self._build_decryption_tab()

    def _build_encryption_tab(self) -> None:
        tab = self.encryption_tab
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(3, weight=1)

        key_frame = ttk.Labelframe(tab, text="Parámetros RSA", padding=10)
        key_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        for index, (label, variable) in enumerate(
            (("p (primo)", self.p), ("q (primo)", self.q), ("e", self.e))
        ):
            ttk.Label(key_frame, text=label).grid(
                row=0, column=index * 2, sticky="w", padx=(0 if index == 0 else 16, 6)
            )
            ttk.Entry(key_frame, textvariable=variable, width=17).grid(
                row=0, column=index * 2 + 1, sticky="w"
            )
        ttk.Label(
            key_frame,
            text="Se requiere 126126 < p × q < 1000000 y MCD(e, φ) = 1.",
            style="Help.TLabel",
        ).grid(row=1, column=0, columnspan=6, sticky="w", pady=(8, 0))

        input_frame = ttk.Labelframe(tab, text="Mensaje M", padding=10)
        input_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        input_frame.columnconfigure(0, weight=1)
        ttk.Label(
            input_frame,
            text="ASCII 032 a 126. Los espacios iniciales, finales y consecutivos se conservan.",
            style="Help.TLabel",
        ).grid(row=0, column=0, sticky="w", pady=(0, 6))
        self.message_input = ScrolledText(input_frame, height=4, font=("Consolas", 11), wrap="word")
        self.message_input.grid(row=1, column=0, sticky="ew")

        buttons = ttk.Frame(tab)
        buttons.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        ttk.Button(buttons, text="Encriptar", command=self._encrypt).grid(row=0, column=0)
        ttk.Button(buttons, text="Cargar ejemplo", command=self._load_example).grid(
            row=0, column=1, padx=(8, 0)
        )
        self.copy_c_button = ttk.Button(
            buttons, text="Copiar C", command=self._copy_ciphertext, state="disabled"
        )
        self.copy_c_button.grid(row=0, column=2, padx=(8, 0))
        self.copy_l_button = ttk.Button(
            buttons, text="Copiar L", command=self._copy_length, state="disabled"
        )
        self.copy_l_button.grid(row=0, column=3, padx=(8, 0))
        self.send_button = ttk.Button(
            buttons,
            text="Pasar a parte 2",
            command=self._send_to_decryption,
            state="disabled",
        )
        self.send_button.grid(row=0, column=4, padx=(8, 0))

        output_frame = ttk.Labelframe(tab, text="Resultado y proceso", padding=10)
        output_frame.grid(row=3, column=0, sticky="nsew")
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(4, weight=1)
        ttk.Label(
            output_frame, textvariable=self.status, style="Status.TLabel", wraplength=780
        ).grid(
            row=0, column=0, sticky="w", pady=(0, 6)
        )
        ttk.Label(
            output_frame, textvariable=self.summary, style="Help.TLabel", wraplength=780
        ).grid(
            row=1, column=0, sticky="w", pady=(0, 7)
        )
        result_labels = ttk.Frame(output_frame)
        result_labels.grid(row=2, column=0, sticky="ew")
        ttk.Label(result_labels, text="Cifrado C:").grid(row=0, column=0, sticky="w")
        ttk.Label(result_labels, text="Longitud original L:").grid(
            row=0, column=1, sticky="w", padx=(30, 6)
        )
        ttk.Entry(
            result_labels, textvariable=self.output_length, width=10, state="readonly"
        ).grid(row=0, column=2, sticky="w")
        self.cipher_output = ScrolledText(
            output_frame, height=2, font=("Consolas", 11), wrap="word", state="disabled"
        )
        self.cipher_output.grid(row=3, column=0, sticky="ew", pady=(3, 8))

        self.detail_tabs = ttk.Notebook(output_frame)
        self.detail_tabs.grid(row=4, column=0, sticky="nsew")
        blocks_panel = ttk.Frame(self.detail_tabs)
        trace_panel = ttk.Frame(self.detail_tabs)
        self.detail_tabs.add(blocks_panel, text="Bloques y códigos ASCII")
        self.detail_tabs.add(trace_panel, text="Cálculo modular")
        blocks_panel.columnconfigure(0, weight=1)
        blocks_panel.rowconfigure(0, weight=1)
        trace_panel.columnconfigure(0, weight=1)
        trace_panel.rowconfigure(0, weight=1)

        columns = ("pair", "ascii", "plain", "cipher")
        self.blocks_table = ttk.Treeview(
            blocks_panel, columns=columns, show="headings", height=8
        )
        for column, heading, width in (
            ("pair", "Pareja", 130),
            ("ascii", "Códigos ASCII", 180),
            ("plain", "m (6 dígitos)", 160),
            ("cipher", "c (6 dígitos)", 160),
        ):
            self.blocks_table.heading(column, text=heading)
            self.blocks_table.column(column, width=width, minwidth=100)
        self.blocks_table.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(blocks_panel, orient="vertical", command=self.blocks_table.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.blocks_table.configure(yscrollcommand=scrollbar.set)
        self.blocks_table.bind("<<TreeviewSelect>>", self._show_selected_trace)
        self.trace_output = ScrolledText(
            trace_panel, font=("Consolas", 10), wrap="word", state="disabled"
        )
        self.trace_output.grid(row=0, column=0, sticky="nsew")
        self._set_trace_output("Seleccione un bloque después de encriptar.")
        ttk.Label(
            output_frame,
            text="Seleccione una fila para ver sus cuadrados sucesivos. Las comillas hacen visibles los espacios.",
            style="Help.TLabel",
        ).grid(row=5, column=0, sticky="w", pady=(5, 0))

    def _build_decryption_tab(self) -> None:
        """Construye entradas, resultado, bloques y traza de desencriptación."""
        tab = self.decryption_tab
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(2, weight=1)

        frame = ttk.Labelframe(tab, text="Entradas de desencriptación", padding=12)
        frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        frame.columnconfigure(1, weight=1)
        for row, (label, variable) in enumerate(
            (
                ("p", self.p),
                ("q", self.q),
                ("e", self.e),
                ("C (bloques de 6 dígitos)", self.ciphertext),
                ("L (longitud original)", self.length),
            )
        ):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=6, padx=(0, 12))
            ttk.Entry(frame, textvariable=variable).grid(row=row, column=1, sticky="ew", pady=6)

        ttk.Label(
            frame,
            text="C usa bloques de seis dígitos separados por un espacio; L se ingresa por separado.",
            style="Help.TLabel",
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(5, 0))

        ttk.Button(tab, text="Desencriptar", command=self._decrypt).grid(
            row=1, column=0, sticky="w", pady=(0, 10)
        )

        output_frame = ttk.Labelframe(tab, text="Mensaje recuperado y proceso", padding=10)
        output_frame.grid(row=2, column=0, sticky="nsew")
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(4, weight=1)
        ttk.Label(
            output_frame,
            textvariable=self.decryption_status,
            style="Status.TLabel",
            wraplength=780,
        ).grid(row=0, column=0, sticky="w", pady=(0, 6))
        ttk.Label(
            output_frame,
            textvariable=self.decryption_summary,
            style="Help.TLabel",
            wraplength=780,
        ).grid(row=1, column=0, sticky="w", pady=(0, 7))
        ttk.Label(output_frame, text="Mensaje M (se conservan todos sus espacios):").grid(
            row=2, column=0, sticky="w"
        )
        self.plaintext_output = ScrolledText(
            output_frame, height=3, font=("Consolas", 11), wrap="word", state="disabled"
        )
        self.plaintext_output.grid(row=3, column=0, sticky="ew", pady=(3, 8))

        self.decryption_detail_tabs = ttk.Notebook(output_frame)
        self.decryption_detail_tabs.grid(row=4, column=0, sticky="nsew")
        blocks_panel = ttk.Frame(self.decryption_detail_tabs)
        trace_panel = ttk.Frame(self.decryption_detail_tabs)
        self.decryption_detail_tabs.add(blocks_panel, text="Bloques recuperados")
        self.decryption_detail_tabs.add(trace_panel, text="Cálculo modular")
        blocks_panel.columnconfigure(0, weight=1)
        blocks_panel.rowconfigure(0, weight=1)
        trace_panel.columnconfigure(0, weight=1)
        trace_panel.rowconfigure(0, weight=1)

        columns = ("cipher", "plain", "ascii", "pair")
        self.decryption_blocks_table = ttk.Treeview(
            blocks_panel, columns=columns, show="headings", height=7
        )
        for column, heading, width in (
            ("cipher", "c (6 dígitos)", 150),
            ("plain", "m (6 dígitos)", 150),
            ("ascii", "Códigos ASCII", 170),
            ("pair", "Pareja", 130),
        ):
            self.decryption_blocks_table.heading(column, text=heading)
            self.decryption_blocks_table.column(column, width=width, minwidth=100)
        self.decryption_blocks_table.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(
            blocks_panel, orient="vertical", command=self.decryption_blocks_table.yview
        )
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.decryption_blocks_table.configure(yscrollcommand=scrollbar.set)
        self.decryption_blocks_table.bind(
            "<<TreeviewSelect>>", self._show_selected_decryption_trace
        )

        self.decryption_trace_output = ScrolledText(
            trace_panel, font=("Consolas", 10), wrap="word", state="disabled"
        )
        self.decryption_trace_output.grid(row=0, column=0, sticky="nsew")
        self._set_decryption_trace_output(
            "Seleccione un bloque después de desencriptar."
        )
        ttk.Label(
            output_frame,
            text="La representación con repr hace visibles los espacios; seleccione una fila para ver c^d mod n.",
            style="Help.TLabel",
        ).grid(row=5, column=0, sticky="w", pady=(5, 0))

    def _encrypt(self) -> None:
        # end-1c elimina únicamente el salto implícito de Tk, no espacios del usuario.
        message = self.message_input.get("1.0", "end-1c")
        try:
            result = encrypt(message, self.p.get(), self.q.get(), self.e.get())
        except ValidationError as exc:
            self._clear_output()
            self.status.set(f"Error: {exc}")
            messagebox.showerror("Datos inválidos", str(exc), parent=self)
            return

        self.latest_result = result
        self.output_length.set(str(result.original_length))
        self.copy_c_button.configure(state="normal")
        self.copy_l_button.configure(state="normal")
        self.send_button.configure(state="normal")
        self.status.set("Mensaje encriptado correctamente.")
        self.summary.set(
            f"n = {result.parameters.n} · φ = {result.parameters.phi} · MCD(e, φ) = 1 · "
            f"llave pública = ({result.parameters.e}, {result.parameters.n})\n"
            f"L = {result.original_length} · relleno: {'sí' if result.filler_added else 'no'}"
        )
        self._set_cipher_output(result.ciphertext)
        for item in self.blocks_table.get_children():
            self.blocks_table.delete(item)
        for block in result.blocks:
            self.blocks_table.insert(
                "",
                "end",
                values=(
                    repr(block.pair),
                    f"{block.ascii_codes[0]:03d} {block.ascii_codes[1]:03d}",
                    block.plaintext_six_digits,
                    block.ciphertext_six_digits,
                ),
            )
        if result.blocks:
            self.blocks_table.selection_set(self.blocks_table.get_children()[0])
            self._show_selected_trace()
        else:
            self._set_trace_output("El mensaje vacío no produce bloques.")

    def _clear_output(self) -> None:
        self.latest_result = None
        self.output_length.set("")
        self.copy_c_button.configure(state="disabled")
        self.copy_l_button.configure(state="disabled")
        self.send_button.configure(state="disabled")
        self.summary.set("Los resultados se mostrarán aquí.")
        self._set_cipher_output("")
        self._set_trace_output("Seleccione un bloque después de encriptar.")
        for item in self.blocks_table.get_children():
            self.blocks_table.delete(item)

    def _decrypt(self) -> None:
        try:
            result = decrypt(
                self.ciphertext.get(),
                self.length.get(),
                self.p.get(),
                self.q.get(),
                self.e.get(),
            )
        except ValidationError as exc:
            self._clear_decryption_output()
            self.decryption_status.set(f"Error: {exc}")
            messagebox.showerror("Datos inválidos", str(exc), parent=self)
            return

        self.latest_decryption_result = result
        self.decryption_status.set("Mensaje desencriptado correctamente.")
        self.decryption_summary.set(
            f"n = {result.parameters.n} · φ = {result.parameters.phi} · d = {result.private_exponent} · "
            f"llave privada = ({result.private_exponent}, {result.parameters.n})\n"
            f"L = {result.original_length} · relleno retirado: "
            f"{'sí' if result.filler_removed else 'no'} · "
            f"antes de retirar relleno = {result.recovered_with_filler!r} · M = {result.message!r}"
        )
        self._set_plaintext_output(result.message)
        for item in self.decryption_blocks_table.get_children():
            self.decryption_blocks_table.delete(item)
        for block in result.blocks:
            self.decryption_blocks_table.insert(
                "",
                "end",
                values=(
                    block.ciphertext_six_digits,
                    block.plaintext_six_digits,
                    f"{block.ascii_codes[0]:03d} {block.ascii_codes[1]:03d}",
                    repr(block.pair),
                ),
            )
        if result.blocks:
            first = self.decryption_blocks_table.get_children()[0]
            self.decryption_blocks_table.selection_set(first)
            self._show_selected_decryption_trace()
        else:
            self._set_decryption_trace_output("El mensaje vacío no produce bloques.")

    def _clear_decryption_output(self) -> None:
        self.latest_decryption_result = None
        self.decryption_summary.set("Los resultados se mostrarán aquí.")
        self._set_plaintext_output("")
        self._set_decryption_trace_output(
            "Seleccione un bloque después de desencriptar."
        )
        for item in self.decryption_blocks_table.get_children():
            self.decryption_blocks_table.delete(item)

    def _set_cipher_output(self, value: str) -> None:
        self.cipher_output.configure(state="normal")
        self.cipher_output.delete("1.0", "end")
        self.cipher_output.insert("1.0", value)
        self.cipher_output.configure(state="disabled")

    def _set_trace_output(self, value: str) -> None:
        self.trace_output.configure(state="normal")
        self.trace_output.delete("1.0", "end")
        self.trace_output.insert("1.0", value)
        self.trace_output.configure(state="disabled")

    def _set_plaintext_output(self, value: str) -> None:
        self.plaintext_output.configure(state="normal")
        self.plaintext_output.delete("1.0", "end")
        self.plaintext_output.insert("1.0", value)
        self.plaintext_output.configure(state="disabled")

    def _set_decryption_trace_output(self, value: str) -> None:
        self.decryption_trace_output.configure(state="normal")
        self.decryption_trace_output.delete("1.0", "end")
        self.decryption_trace_output.insert("1.0", value)
        self.decryption_trace_output.configure(state="disabled")

    def _show_selected_trace(self, _event: tk.Event | None = None) -> None:
        if self.latest_result is None or not self.blocks_table.selection():
            return
        selected = self.blocks_table.selection()[0]
        block = self.latest_result.blocks[self.blocks_table.index(selected)]
        parameters = self.latest_result.parameters
        ciphertext, steps = modular_power_trace(
            block.numeric_plaintext, parameters.e, parameters.n
        )
        lines = [
            f"Bloque {block.position}: {block.pair!r} = {block.plaintext_six_digits}",
            f"c = m^e mod n = {block.numeric_plaintext}^{parameters.e} mod {parameters.n}",
            "Inicio: acumulador = 1; base = m mod n.",
            "",
        ]
        for step in steps:
            lines.append(
                f"Paso {step.iteration}: exponente = {step.exponent_before} "
                f"({'impar' if step.multiplied else 'par'})"
            )
            if step.multiplied:
                lines.append(
                    f"  acumulador = ({step.result_before} × {step.base_before}) "
                    f"mod {parameters.n} = {step.result_after}"
                )
            else:
                lines.append(f"  acumulador = {step.result_before} (no se multiplica)")
            lines.append(
                f"  base siguiente = ({step.base_before} × {step.base_before}) "
                f"mod {parameters.n} = {step.base_after}; "
                f"exponente siguiente = {step.exponent_before // 2}"
            )
        lines.extend(("", f"Resultado: c = {ciphertext:06d}"))
        self._set_trace_output("\n".join(lines))

    def _show_selected_decryption_trace(self, _event: tk.Event | None = None) -> None:
        if (
            self.latest_decryption_result is None
            or not self.decryption_blocks_table.selection()
        ):
            return
        selected = self.decryption_blocks_table.selection()[0]
        block = self.latest_decryption_result.blocks[
            self.decryption_blocks_table.index(selected)
        ]
        parameters = self.latest_decryption_result.parameters
        exponent = self.latest_decryption_result.private_exponent
        plaintext, steps = modular_power_trace(
            block.numeric_ciphertext, exponent, parameters.n
        )
        lines = [
            f"Bloque {block.position}: c = {block.ciphertext_six_digits}",
            f"m = c^d mod n = {block.numeric_ciphertext}^{exponent} mod {parameters.n}",
            "Inicio: acumulador = 1; base = c mod n.",
            "",
        ]
        for step in steps:
            lines.append(
                f"Paso {step.iteration}: exponente = {step.exponent_before} "
                f"({'impar' if step.multiplied else 'par'})"
            )
            if step.multiplied:
                lines.append(
                    f"  acumulador = ({step.result_before} × {step.base_before}) "
                    f"mod {parameters.n} = {step.result_after}"
                )
            else:
                lines.append(f"  acumulador = {step.result_before} (no se multiplica)")
            lines.append(
                f"  base siguiente = ({step.base_before} × {step.base_before}) "
                f"mod {parameters.n} = {step.base_after}; "
                f"exponente siguiente = {step.exponent_before // 2}"
            )
        lines.extend(
            (
                "",
                f"Resultado: m = {plaintext:06d}",
                f"ASCII: {block.ascii_codes[0]:03d} {block.ascii_codes[1]:03d} = {block.pair!r}",
            )
        )
        self._set_decryption_trace_output("\n".join(lines))

    def _load_example(self) -> None:
        self._clear_output()
        self.p.set("367")
        self.q.set("373")
        self.e.set("17")
        self.message_input.delete("1.0", "end")
        self.message_input.insert("1.0", "RSA")
        self.status.set("Ejemplo cargado. Pulse Encriptar.")

    def _copy_ciphertext(self) -> None:
        if self.latest_result is None:
            return
        self.clipboard_clear()
        self.clipboard_append(self.latest_result.ciphertext)
        self.status.set("C copiado al portapapeles.")

    def _copy_length(self) -> None:
        if self.latest_result is None:
            return
        self.clipboard_clear()
        self.clipboard_append(str(self.latest_result.original_length))
        self.status.set("L copiada al portapapeles.")

    def _send_to_decryption(self) -> None:
        if self.latest_result is None:
            messagebox.showinfo("Sin resultado", "Primero encripte un mensaje.", parent=self)
            return
        self.p.set(str(self.latest_result.parameters.p))
        self.q.set(str(self.latest_result.parameters.q))
        self.e.set(str(self.latest_result.parameters.e))
        self.ciphertext.set(self.latest_result.ciphertext)
        self.length.set(str(self.latest_result.original_length))
        self._clear_decryption_output()
        self.decryption_status.set(
            "Datos transferidos desde la encriptación. Pulse Desencriptar."
        )
        self.tabs.select(self.decryption_tab)


if __name__ == "__main__":
    RSAApp().mainloop()
