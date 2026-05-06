---
layout: default
title: Changelog
parent: .NET API Reference
nav_order: 99
description: "Release notes and version history for AntiSSRF .NET Library"
---

# Changelog

All notable changes to the AntiSSRF .NET Library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

Nothing yet.

## v1.0.0

Initial version of the open-source Microsoft AntiSSRF Library for .NET.
* `AntiSSRFPolicy` - Used to customize protection policies applied on all requests by `AntiSSRFHandler`.
* `AntiSSRFHandler` - Implementation of .NET `HttpMessageHandler` that applies security policies on all requests.
* `URIValidator` - Provides three methods for validating the domain of a URL: `InAzureKeyVaultDomain`, `InAzureStorageDomain`, and `InDomain`.

## Thank you to all our original developers!

We are deeply grateful to our original contributors. We truly couldn't have gotten where we are today without you. Your years of dedicated hard work made this entire project possible. Thank you so much!

* [Arjun Gopalakrishna](https://github.com/247arjun)
* [Emmie Teng](https://github.com/EmmieBunnie)
* Kyndell Geddis
* [Leah Restad](https://github.com/leah-restad)
* Likhitesh S
* [Michael Hendrickx](https://github.com/ndrix)
* [Stephen Toub](https://github.com/stephentoub)
* [Susan Krkasharian](https://github.com/susan-krkasharian)
