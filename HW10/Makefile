.PHONY: analyze ssllabs pdf clean cleanall help all

# Target servers for analysis
SERVERS = www.google.com www.cloudflare.com github.com

# Files
TEX_FILE = HW10_Nicolas_Leone_1986354.tex
PDF_FILE = HW10_Nicolas_Leone_1986354.pdf
ANALYSIS_SCRIPT = analyze_tls.py
SSLLABS_SCRIPT = ssllabs_check.py

# Default target
all: analyze ssllabs pdf

# Run OpenSSL TLS analysis
analyze:
	@echo "🔍 Analyzing TLS configurations with OpenSSL..."
	@mkdir -p results
	@python3 $(ANALYSIS_SCRIPT) $(SERVERS)
	@echo "✅ OpenSSL analysis complete!"

# Query SSL Labs
ssllabs:
	@echo "🌐 Querying SSL Labs API..."
	@mkdir -p results
	@python3 $(SSLLABS_SCRIPT) $(SERVERS)
	@echo "✅ SSL Labs check complete!"

# Analyze single server
test:
	@echo "🧪 Running quick test on www.google.com..."
	@python3 $(ANALYSIS_SCRIPT) www.google.com
	@echo "✅ Test complete!"

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

# Clean everything including PDF and analysis results
cleanall: clean
	@echo "🧹 Removing all generated files..."
	@rm -f $(PDF_FILE)
	@rm -rf results/
	@echo "✅ Full cleanup complete!"

# Help
help:
	@echo "Available targets:"
	@echo "  all        - Run analyses and compile PDF (default)"
	@echo "  analyze    - Perform OpenSSL TLS analysis"
	@echo "  ssllabs    - Query SSL Labs API"
	@echo "  test       - Quick test on single server"
	@echo "  pdf        - Compile LaTeX document"
	@echo "  clean      - Remove temporary files"
	@echo "  cleanall   - Remove all generated files"
	@echo "  help       - Show this help message"
