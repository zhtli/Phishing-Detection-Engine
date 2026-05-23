from phishing_engine.registry import register_stage
from phishing_engine.stages.url_stage import UrlStage
from phishing_engine.stages.domain_stage import DomainStage
from phishing_engine.stages.content_stage import ContentStage

register_stage("url", UrlStage)
register_stage("domain", DomainStage)
register_stage("content", ContentStage)
