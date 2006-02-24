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

(define %root-filename%
	;; Nom du fichier HTML principal
	"index"
)

(define %stylesheet%
	;; Nom et emplacement de la feuille de style (CSS) utilisée par les pages HTML
	"../wzdftpd-docs.css"
)

(define %css-decoration%
	;; Active l'utilisation des CSS dans le code HTML généré.
	;; Notament les parametres CLASS= des principales balises
	#t)

(define %body-attr% 
	;; Attribut utilisé dans la balise BODY
	;; Ici on laisse faire la feuille de style CSS
	(list
	)
)


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
