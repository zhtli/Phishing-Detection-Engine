from phishing_engine.core.registry import register_stage
from phishing_engine.stages.url import UrlStage
from phishing_engine.stages.domain import DomainStage
from phishing_engine.stages.content import ContentStage

register_stage("url", UrlStage)
register_stage("domain", DomainStage)
register_stage("content", ContentStage)
