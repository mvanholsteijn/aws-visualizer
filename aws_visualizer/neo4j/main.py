import logging
import os

from neomodel import db, install_all_labels

import aws_visualizer.neo4j.ec2_instance
import aws_visualizer.neo4j.elb
import aws_visualizer.neo4j.elbv2
import aws_visualizer.neo4j.function
import aws_visualizer.neo4j.rds
import aws_visualizer.neo4j.redshift
import aws_visualizer.neo4j.security_group


class AWSNeo4jImporter(object):
    def __init__(self):
        self.url = os.getenv('NEO4J_BOLT_URL', 'bolt://neo4j:neo4j@localhost:7687')

    def login(self):
        db.set_connection(self.url)
        install_all_labels()

    def load(self):
        aws_visualizer.neo4j.security_group.load()
        aws_visualizer.neo4j.ec2_instance.load()
        aws_visualizer.neo4j.elb.load()
        aws_visualizer.neo4j.elbv2.load()
        aws_visualizer.neo4j.rds.load()
        aws_visualizer.neo4j.redshift.load()
        aws_visualizer.neo4j.function.load()

def main():
    logging.basicConfig(level=os.getenv('LOG_LEVEL', 'ERROR'))
    importer = AWSNeo4jImporter()
    importer.load()


if __name__ == '__main__':
    main()
