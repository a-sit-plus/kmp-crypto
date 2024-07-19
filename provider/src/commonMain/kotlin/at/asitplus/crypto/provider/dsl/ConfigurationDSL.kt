package at.asitplus.crypto.provider.dsl

/**
 * The meta functionality that enables us to easily create DSLs.
 * @see at.asitplus.crypto.provider.dsl.DSLInheritanceDemonstration
 * @see at.asitplus.crypto.provider.dsl.DSLVarianceDemonstration
 */
object DSL {
    /** Resolve a DSL lambda to a concrete configuration */
    fun <S: DSL.Data, T: S> resolve(factory: ()->T, config: DSLConfigureFn<S>): T =
        (if (config == null) factory() else factory().apply(config)).also(DSL.Data::validate)

    sealed interface Holder<out T> {
        val v: T
    }

    sealed interface Invokable<out Storage, out Target: Any>: Holder<Storage> {
        operator fun invoke(configure: Target.()->Unit)
    }

    /** Constructed by: [DSL.Data.child]. */
    class DirectHolder<out T: DSL.Data?> internal constructor(default: T, private val factory: ()->(T & Any))
        : Invokable<T,T&Any> {
        private var _v: T = default
        override val v: T get() = _v

        override operator fun invoke(configure: (T & Any).()->Unit) { _v = resolve(factory, configure) }
    }

    /** Constructed by: [DSL.Data.subclassOf]. */
    class Generalized<out T: DSL.Data?> internal constructor(default: T): Holder<T> {
        private var _v: T = default
        override val v: T get() = _v

        inner class option<out S:T&Any>
        /**
         * Adds a specialized invokable accessor for the underlying generalized storage.
         * Use as `val specialized = _holder.option(::SpecializedClass).`
         *
         * User code can invoke this specialized accessor as `specialized { }`.
         * This constructs a new specialized child, configures it using the specified block,
         * and stores it in the underlying generalized storage.
         */
        internal constructor(private val factory: ()->S) : Invokable<T,S> {
            override val v: T get() = this@Generalized.v
            override operator fun invoke(configure: S.()->Unit) { _v = resolve(factory, configure) }
        }
    }

    /** Constructed by: [DSL.Data.integratedReceiver]. */
    class Integrated<T: Any> internal constructor(): Invokable<(T.()->Unit)?, T> {
        private var _v: (T.()->Unit)? = null
        override val v: (T.()->Unit)? get() = _v
        override operator fun invoke(configure: T.()->Unit) { _v = configure }
    }

    @DslMarker
    annotation class Marker

    /** The superclass of all DSL configuration objects. Exposes helper functions for definition. */
    @Marker
    open class Data {
        /**
         * Embeds a child; use as `val sub = child(::TypeOfSub)`.
         * Defaults to a default-constructed child.
         *
         * User code will invoke as `sub { }`.
         * This constructs a new child and configures it using the specified block.
         */
        protected fun <T: DSL.Data> child(factory: ()->T): Invokable<T,T> =
            DirectHolder<T>(factory(), factory)

        /**
         * Embeds an optional child. Use as `val sub = childOrNull(::TypeOfSub)`.
         * Defaults to `null`.
         *
         * User code will invoke as `sub { }`
         * This constructs a new child and configures it using the specified block.
         */
        protected fun <T: DSL.Data> childOrNull(factory: ()->T): Invokable<T?,T> =
            DirectHolder<T?>(null, factory)

        /**
         * Embeds an optional child. Use as `val sub = childOrDefault(::TypeOfSub) { ... }
         * Defaults to a child pre-configured using the specified block.
         *
         * User code will invoke as `sub { }`
         * This constructs a new child and configures it using the specified block.
         * Note that the specified default block is **not** applied if user code configures the child.
         */
        protected fun <T: DSL.Data> childOrDefault(factory: ()->T, default: T.()->Unit): Invokable<T,T> =
            DirectHolder<T>(factory().also(default), factory)

        /**
         * Specifies a generalized holder of type T.
         * Use as `internal val _subHolder = subclassOf<GeneralTypeOfSub>()`.
         *
         * The generalized holder itself cannot be invoked, and should be marked `internal`.
         * Defaults to `null`.
         *
         * Specialized invokable accessors can be spun off via `.option(::SpecializedClass)`.
         * @see DSL.Generalized.option
         */
        protected fun <T: DSL.Data> subclassOf(): Generalized<T?> =
            Generalized<T?>(null)
        /**
         * Specifies a generalized holder of type T.
         * Use as `internal val _subHolder = subclassOf<GeneralTypeOfSub>(SpecializedClass())`.
         *
         * The generalized holder itself cannot be invoked, and should be marked `internal`.
         * Defaults to the specified `default`.
         *
         * Specialized invokable accessors can be spun off via `.option(::SpecializedClass)`.
         * @see DSL.Generalized.option
         */
        protected fun <T: DSL.Data> subclassOf(default: T): Generalized<T> =
            Generalized<T>(default)

        /**
         * Integrates an external configuration lambda into the DSL.
         * Use as `val other = integratedReceiver<ExternalType>()`.
         *
         * This receiver can be invoked, but simply stores the received lambda instead of running it.
         * Defaults to `null`.
         */
        protected fun <T: Any> integratedReceiver(): Integrated<T> =
            Integrated<T>()

        /**
         * Invoked by `DSL.resolve()` after the configuration block runs.
         * Can be used for sanity checks.
         */
        internal open fun validate() {}
    }
}

typealias DSLConfigureFn<T> = (T.()->Unit)?
