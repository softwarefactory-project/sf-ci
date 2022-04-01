#!/usr/bin/env python3

import argparse
import elasticsearch


def get_arguments():
    parser = argparse.ArgumentParser(description="Check log directories "
                                     "and push to the Opensearch service")
    parser.add_argument("--host",
                        help="Opensearch host",
                        default='localhost')
    parser.add_argument("--port",
                        help="Opensearch port",
                        type=int,
                        default=9200)
    parser.add_argument("--username",
                        help="Opensearch username",
                        default='logstash')
    parser.add_argument("--password", help="Opensearch user password")
    parser.add_argument("--index",
                        help="Opensearch index",
                        default=['logstash', 'zuul'],
                        action='append')
    parser.add_argument("--insecure",
                        help="Skip validating SSL cert",
                        action="store_false")
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = get_arguments()
    es_creds = {
            "host": args.host,
            "port": args.port,
            "use_ssl": True,
        }

    if args.username and args.password:
        es_creds["http_auth"] = "%s:%s" % (args.username, args.password)

    es_client = elasticsearch.Elasticsearch([es_creds], timeout=60,
                                            verify_certs=args.insecure)
    for indices in es_client.indices.get_alias("*"):
        for index in args.index:
            if index in indices:
                es_client.indices.delete(indices)
