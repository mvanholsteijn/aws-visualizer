mkdir -p target
python graph_region.py > target/region.dot
dot -Tpng -o target/region.png target/region.dot
open target/region.png
