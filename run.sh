mkdir -p target
rm -rf target/*.dot target/*.png
python graph_region.py  --directory target $@
for file in target/*.dot; do
	dot -Tpng -o target/$(basename $file .dot).png  $file
done
open target/*.png
