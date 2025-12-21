.PHONY: build run test logs clean cleanall pdf help

# Docker targets
build:
	@echo "🔨 Building Docker images..."
	docker-compose build

run:
	@echo "🔒 Starting SafeGuard VPN..."
	docker-compose up

test:
	@echo "🧪 Running VPN performance test..."
	@$(MAKE) build
	@docker-compose up --abort-on-container-exit
	@echo "✅ Test complete!"

logs:
	@echo "📋 Showing logs..."
	docker-compose logs -f

clean-docker:
	@echo "🧹 Cleaning Docker containers and networks..."
	docker-compose down
	@echo "✅ Docker cleanup complete!"

# Performance benchmarking
benchmark:
	@echo "📊 Running performance benchmark..."
	@docker-compose up client --abort-on-container-exit
	@echo "✅ Benchmark complete!"

# LaTeX targets
pdf:
	@echo "📄 Compiling LaTeX document..."
	@pdflatex -interaction=nonstopmode HW09_Nicolas_Leone_1986354.tex > /dev/null 2>&1 || true
	@pdflatex -interaction=nonstopmode HW09_Nicolas_Leone_1986354.tex > /dev/null 2>&1 || true
	@pdflatex -interaction=nonstopmode HW09_Nicolas_Leone_1986354.tex > /dev/null 2>&1 || true
	@echo "🧹 Cleaning temporary files..."
	@rm -f *.aux *.log *.out *.toc
	@echo "✅ Done! PDF generated: HW09_Nicolas_Leone_1986354.pdf"

# Cleanup targets
clean:
	@echo "🧹 Cleaning temporary files..."
	@rm -f *.aux *.log *.out *.toc
	@echo "✅ Cleanup complete!"

cleanall: clean clean-docker
	@echo "🧹 Removing PDF..."
	@rm -f HW09_Nicolas_Leone_1986354.pdf
	@docker rmi -f hw09-client hw09-server 2>/dev/null || true
	@echo "✅ Full cleanup complete!"

help:
	@echo "Available targets:"
	@echo "  build        - Build Docker images"
	@echo "  run          - Run the VPN demonstration"
	@echo "  test         - Build and run performance test"
	@echo "  benchmark    - Run performance benchmark only"
	@echo "  logs         - Show Docker logs"
	@echo "  pdf          - Compile LaTeX document"
	@echo "  clean        - Remove temporary files"
	@echo "  clean-docker - Remove Docker containers"
	@echo "  cleanall     - Full cleanup (files + Docker + PDF)"
