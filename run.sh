rm -rf target
mkdir -p target/default
mkdir -p target/external
mkdir -p target/subnets

python graph_region.py  --directory target/default 
python graph_region.py  --directory target/subnets --use-subgraphs 
python graph_region.py  --directory target/external --show-external-only --use-subgraphs 


for file in target/*/*.dot; do
	dot -Tpng -o $(dirname $file)/$(basename $file .dot).png  $file
done
open target/*/*.png
