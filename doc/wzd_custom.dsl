<!DOCTYPE style-sheet PUBLIC "-//James Clark//DTD DSSSL Style Sheet//EN" [
<!ENTITY dbstyle PUBLIC "-//Norman Walsh//DOCUMENT DocBook Print Stylesheet//EN" CDATA DSSSL>
<!ENTITY html-ss 
  PUBLIC "-//Norman Walsh//DOCUMENT DocBook HTML Stylesheet//EN" CDATA dsssl>
]>

<style-sheet>
<style-specification id="utils" use="docbook">
<style-specification-body>

;; ===================================================================
;; Generic Parameters
;; (Generic currently means: both print and html)

(define %chapter-autolabel% #t)
(define %section-autolabel% #t)
(define (toc-depth nd) 3)

(define %root-filename% "index")   ;; name for the root html file
(define %use-id-as-filename% #t)   ;; if #t uses ID value, if present, as filename
                                   ;;   otherwise a code is used to indicate level
                                   ;;   of chunk, and general element number
                                   ;;   (nth element in the document)
(define use-output-dir #f)         ;; output in separate directory?
(define %output-dir% "HTML")       ;; if output in directory, it's called HTML

</style-specification-body>
</style-specification>

<style-specification id="html" use="utils">
<style-specification-body>

;; ===================================================================
;; HTML Parameters
;; Call: jade -d wzd_custom.dsl#html

(define %html-ext% ".html")        ;; default extension for html output files
(define %html-prefix% "")	   ;; prefix for all filenames generated (except root)


</style-specification-body>
</style-specification>

<style-specification id="php" use="utils">
<style-specification-body>

;; ===================================================================
;; HTML Parameters
;; Call: jade -d wzd_custom.dsl#php

(define %html-ext% ".php")         ;; default extension for html output files
(define %html-prefix% "")	   ;; prefix for all filenames generated (except root)


</style-specification-body>
</style-specification>

<external-specification id="docbook" document="html-ss">
</style-sheet>
