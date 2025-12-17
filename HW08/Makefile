.PHONY: analyze pdf clean cleanall help all

# Files
TEX_FILE = HW08_Nicolas_Leone_1986354.tex
PDF_FILE = HW08_Nicolas_Leone_1986354.pdf
SIGNED_PDF = test_signed.pdf
ANALYSIS_SCRIPT = analyze_signature.py

# Default target
all: analyze pdf

# Run signature analysis
analyze:
	@echo "🔍 Analyzing digital signature in $(SIGNED_PDF)..."
	@python3 $(ANALYSIS_SCRIPT) $(SIGNED_PDF)
	@echo "✅ Analysis complete!"

# Extract certificates
certs:
	@echo "📜 Extracting certificates..."
	@python3 $(ANALYSIS_SCRIPT) --extract-certs $(SIGNED_PDF)
	@echo "✅ Certificates extracted!"

# Check OCSP status
ocsp:
	@echo "🌐 Querying OCSP responder..."
	@python3 $(ANALYSIS_SCRIPT) --ocsp $(SIGNED_PDF)
	@echo "✅ OCSP check complete!"

# Analyze CRL
crl:
	@echo "📋 Analyzing CRL..."
	@python3 $(ANALYSIS_SCRIPT) --crl $(SIGNED_PDF)
	@echo "✅ CRL analysis complete!"

# Compile LaTeX document
pdf: $(TEX_FILE)
	@echo "📄 Compiling LaTeX document..."
	@pdflatex -interaction=nonstopmode $(TEX_FILE) > /dev/null 2>&1 || true
	@pdflatex -interaction=nonstopmode $(TEX_FILE) > /dev/null 2>&1 || true
	@pdflatex -interaction=nonstopmode $(TEX_FILE) > /dev/null 2>&1 || true
	@echo "🧹 Cleaning temporary files..."
	@rm -f *.aux *.log *.out *.toc
	@echo "✅ Done! PDF generated: $(PDF_FILE)"

# Clean temporary files
clean:
	@echo "🧹 Cleaning temporary LaTeX files..."
	@rm -f *.aux *.log *.out *.toc
	@echo "✅ Cleanup complete!"

# Clean everything including PDF and analysis outputs
cleanall: clean
	@echo "🧹 Removing all generated files..."
	@rm -f $(PDF_FILE)
	@rm -f cert_*.pem cert_*.der
	@rm -f crl.pem crl.der
	@rm -f ocsp_response.txt
	@rm -f analysis_results.txt
	@echo "✅ Full cleanup complete!"

# Help
help:
	@echo "Available targets:"
	@echo "  all        - Run analysis and compile PDF (default)"
	@echo "  analyze    - Perform complete signature analysis"
	@echo "  certs      - Extract certificate chain"
	@echo "  ocsp       - Query OCSP responder"
	@echo "  crl        - Download and analyze CRL"
	@echo "  pdf        - Compile LaTeX document"
	@echo "  clean      - Remove temporary files"
	@echo "  cleanall   - Remove all generated files"
	@echo "  help       - Show this help message"
